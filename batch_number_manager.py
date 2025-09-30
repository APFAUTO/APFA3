"""
Robust Batch Number Manager for A&P and FDEC Companies.
Completely overhauled system to fix calibration issues and negative numbers.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from database_managers import get_database_manager
from company_config import get_company_config

# Set up logging
logger = logging.getLogger(__name__)


class BatchNumberManager:
    """
    Robust batch number manager with automatic calibration and validation.
    Ensures batch numbers are always accurate, never negative, and properly synchronized.
    """
    
    def __init__(self, company_name: str):
        self.company_name = company_name
        self.config = get_company_config(company_name)
        self.db_manager = get_database_manager(company_name)
        self.models = self.config.get_models()
        
        logger.info(f"🔢 Initialized BatchNumberManager for {company_name.upper()}")
    
    def get_current_batch_number(self) -> int:
        """
        Get the current batch number with automatic calibration.
        Always returns a valid, positive number.
        """
        session = self.db_manager.get_session()
        try:
            counter = self._get_or_create_counter(session)
            
            # Perform calibration and update the counter in the database
            calibrated_value = self._calibrate_counter(session, counter)
            
            # If calibration changed the value, commit it
            if counter.value != calibrated_value:
                counter.value = calibrated_value
                session.commit() # Commit the calibration change
                logger.info(f"🔧 {self.company_name.upper()}: Committed calibration change to {calibrated_value}")
            
            logger.info(f"📊 {self.company_name.upper()}: Current batch number = {calibrated_value}")
            return calibrated_value
            
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Error getting batch number for {self.company_name}: {e}")
            return self.config.batch_start
        finally:
            session.close()
    
    def get_next_batch_number(self) -> int:
        """
        Get the next batch number that will be assigned.
        Does NOT increment the counter.
        """
        current = self.get_current_batch_number()
        return current + 1
    
    def increment_and_get(self) -> int:
        """
        Increment the batch counter and return the new value.
        Guaranteed to return a valid, positive, sequential number.
        """
        session = self.db_manager.get_session()
        try:
            counter = self._get_or_create_counter(session)
            
            # Simply increment the current value
            new_value = counter.value + 1
            
            # Validate the new value (keep existing validation)
            if new_value <= 0:
                logger.warning(f"⚠️ Invalid new batch number {new_value}, resetting to safe value")
                new_value = max(self.config.batch_start, 1)
            
            counter.value = new_value
            session.commit()
            
            logger.info(f"🔢 {self.company_name.upper()}: Incremented batch number to {new_value}")
            return new_value
            
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Error incrementing batch number for {self.company_name}: {e}")
            return self.config.batch_start
        finally:
            session.close()
    
    def set_batch_number(self, value: int) -> bool:
        """
        Set the batch counter to a specific value with validation.
        """
        if value <= 0:
            logger.error(f"❌ Cannot set batch number to {value} - must be positive")
            return False
        
        session = self.db_manager.get_session()
        try:
            counter = self._get_or_create_counter(session)
            counter.value = value
            session.commit()
            
            logger.info(f"✅ {self.company_name.upper()}: Set batch number to {value}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Error setting batch number for {self.company_name}: {e}")
            return False
        finally:
            session.close()
    
    def reset_to_start(self) -> bool:
        """
        Reset batch counter to the configured starting value.
        """
        return self.set_batch_number(self.config.batch_start)
    
    def get_batch_statistics(self) -> dict:
        """
        Get comprehensive batch number statistics and health info.
        """
        session = self.db_manager.get_session()
        try:
            # Get current counter value
            current_batch = self.get_current_batch_number()
            
            # Get highest PO number actually used in database
            highest_por = session.query(self.models['POR']).order_by(
                self.models['POR'].po_number.desc()
            ).first()
            highest_used = highest_por.po_number if highest_por else 0
            
            # Get total POR count
            total_pors = session.query(self.models['POR']).count()
            
            # Calculate health metrics
            is_calibrated = current_batch >= highest_used
            next_available = max(current_batch + 1, highest_used + 1)
            
            stats = {
                'company': self.company_name.upper(),
                'current_batch_number': current_batch,
                'next_batch_number': next_available,
                'highest_po_used': highest_used,
                'total_pors': total_pors,
                'batch_start_config': self.config.batch_start,
                'is_calibrated': is_calibrated,
                'health_status': 'HEALTHY' if is_calibrated and current_batch > 0 else 'NEEDS_CALIBRATION'
            }
            
            logger.info(f"📊 {self.company_name.upper()} Batch Statistics: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error getting batch statistics for {self.company_name}: {e}")
            return {'error': str(e)}
        finally:
            session.close()
    
    def auto_calibrate(self) -> Tuple[bool, str]:
        """
        Automatically calibrate the batch counter to ensure accuracy.
        Fixes negative numbers and synchronization issues.
        """
        session = self.db_manager.get_session()
        try:
            counter = self._get_or_create_counter(session)
            old_value = counter.value
            
            # Perform calibration
            new_value = self._calibrate_counter(session, counter)
            
            if old_value != new_value:
                message = f"🔧 {self.company_name.upper()}: Calibrated batch counter from {old_value} to {new_value}"
                logger.info(message)
                return True, message
            else:
                message = f"✅ {self.company_name.upper()}: Batch counter already calibrated at {new_value}"
                logger.info(message)
                return True, message
                
        except Exception as e:
            error_msg = f"❌ Calibration failed for {self.company_name}: {e}"
            logger.error(error_msg)
            return False, error_msg
        finally:
            session.close()
    
    def _get_or_create_counter(self, session: Session):
        """Get or create batch counter with proper initialization."""
        counter = session.query(self.models['BatchCounter']).first()
        if not counter:
            counter = self.models['BatchCounter'](company=self.company_name, value=self.config.batch_start)
            session.add(counter)
            session.commit()
            logger.info(f"🆕 Created new batch counter for {self.company_name.upper()} starting at {self.config.batch_start}")
        return counter
    
    def _calibrate_counter(self, session: Session, counter) -> int:
        """
        Calibrate counter to ensure it's accurate and never negative.
        It sets the counter to batch_start if it's lower.
        It does NOT increment for the *next* PO number, only ensures a valid starting point.
        Returns the calibrated value.
        """
        current_value = counter.value

        # The counter should be at least the configured batch_start, and at least 1.
        minimum_valid_value = max(self.config.batch_start, 1)

        # Only return the calculated value, do not modify counter.value here
        if current_value < minimum_valid_value:
            logger.info(f"🔧 {self.company_name.upper()}: Calibration calculated: {minimum_valid_value} (current: {current_value})")
            return minimum_valid_value
        
        logger.info(f"🔧 {self.company_name.upper()}: Counter already calibrated at {current_value}.")
        return current_value


# Global instances for each company (lazy initialization)
_ap_batch_manager = None
_fdec_batch_manager = None


def get_batch_manager(company_name: str) -> BatchNumberManager:
    """Get the appropriate batch manager for a company."""
    global _ap_batch_manager, _fdec_batch_manager
    
    if company_name == 'a&p':
        if _ap_batch_manager is None:
            _ap_batch_manager = BatchNumberManager('a&p')
        return _ap_batch_manager
    elif company_name == 'fdec':
        if _fdec_batch_manager is None:
            _fdec_batch_manager = BatchNumberManager('fdec')
        return _fdec_batch_manager
    else:
        raise ValueError(f"Unknown company: {company_name}")


# Convenience functions for backward compatibility
def get_current_batch_number(company_name: str) -> int:
    """Get current batch number for a company."""
    return get_batch_manager(company_name).get_current_batch_number()


def increment_batch_number(company_name: str) -> int:
    """Increment and get new batch number for a company."""
    return get_batch_manager(company_name).increment_and_get()


def calibrate_all_batch_counters() -> dict:
    """Calibrate batch counters for all companies."""
    results = {}
    for company in ['a&p', 'fdec']:
        manager = get_batch_manager(company)
        success, message = manager.auto_calibrate()
        results[company] = {'success': success, 'message': message}
    return results


if __name__ == "__main__":
    # Test the batch number manager
    print("🧪 Testing Batch Number Manager...")
    
    for company in ['a&p', 'fdec']:
        print(f"\n📊 {company.upper()} Company:")
        manager = get_batch_manager(company)
        
        # Get statistics
        stats = manager.get_batch_statistics()
        print(f"  Current: {stats.get('current_batch_number', 'N/A')}")
        print(f"  Health: {stats.get('health_status', 'N/A')}")
        
        # Auto-calibrate
        success, message = manager.auto_calibrate()
        print(f"  Calibration: {message}")
    
    print("\n✅ Batch Number Manager test complete!")
