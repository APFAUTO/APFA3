"""
Independent Application Interface for A&P and FDEC Companies.
Each company can be worked on completely independently without affecting the other.
"""

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash
from company_config import get_ap_config, get_fdec_config, get_company_config
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IndependentPORApp:
    """Base class for independent POR applications."""
    
    def __init__(self, company_name):
        self.company_name = company_name
        self.config = get_company_config(company_name)
        self.models = self.config.get_models()
        
        logger.info(f"✅ Initialized independent {company_name.upper()} POR application")
    
    def get_session(self):
        """Get database session for this company only."""
        return self.config.get_session()
    
    def process_por_upload(self, file_data, por_data):
        """Process POR upload for this company only."""
        session = self.get_session()
        try:
            # Create POR record using this company's models
            por = self.models['POR'](
                po_number=por_data['po_number'],
                requestor_name=por_data['requestor_name'],
                date_order_raised=por_data['date_order_raised'],
                filename=por_data['filename'],
                company=self.company_name,
                # Add FDEC warning check specific to this company
                fdec_warning=self.config.check_fdec_warning(por_data.get('job_contract_no')),
                **por_data
            )
            
            session.add(por)
            session.commit()
            
            logger.info(f"✅ {self.company_name.upper()}: Successfully saved POR #{por_data['po_number']}")
            return True, f"POR saved to {self.company_name.upper()} database", por.id
            
        except Exception as e:
            session.rollback()
            logger.error(f"❌ {self.company_name.upper()}: Error saving POR: {e}")
            return False, str(e), None
        finally:
            session.close()
    
    def get_por_list(self, filters=None):
        """Get POR list for this company only."""
        session = self.get_session()
        try:
            query = session.query(self.models['POR'])
            
            # Apply company-specific filters
            if filters:
                if filters.get('stage'):
                    query = query.filter(self.models['POR'].current_stage == filters['stage'])
                if filters.get('requestor'):
                    query = query.filter(self.models['POR'].requestor_name.contains(filters['requestor']))
            
            pors = query.order_by(self.models['POR'].created_at.desc()).all()
            logger.info(f"📊 {self.company_name.upper()}: Retrieved {len(pors)} PORs")
            return pors
            
        except Exception as e:
            logger.error(f"❌ {self.company_name.upper()}: Error retrieving PORs: {e}")
            return []
        finally:
            session.close()
    
    def update_por_stage(self, por_id, new_stage, comments=None):
        """Update POR stage for this company only."""
        session = self.get_session()
        try:
            por = session.query(self.models['POR']).filter_by(id=por_id).first()
            if not por:
                return False, "POR not found"
            
            # Update stage
            old_stage = por.current_stage
            por.current_stage = new_stage
            por.stage_updated_at = datetime.now(timezone.utc)
            
            # Add comments based on stage
            if new_stage == 'sent' and comments:
                por.sent_comments = comments
            elif new_stage == 'filed' and comments:
                por.filed_comments = comments
            elif new_stage == 'received' and comments:
                por.received_comments = comments
            
            session.commit()
            
            logger.info(f"✅ {self.company_name.upper()}: Updated POR #{por.po_number} from {old_stage} to {new_stage}")
            return True, f"POR stage updated to {new_stage}"
            
        except Exception as e:
            session.rollback()
            logger.error(f"❌ {self.company_name.upper()}: Error updating POR stage: {e}")
            return False, str(e)
        finally:
            session.close()
    
    def get_statistics(self):
        """Get statistics for this company only."""
        session = self.get_session()
        try:
            total_pors = session.query(self.models['POR']).count()
            received_count = session.query(self.models['POR']).filter_by(current_stage='received').count()
            sent_count = session.query(self.models['POR']).filter_by(current_stage='sent').count()
            filed_count = session.query(self.models['POR']).filter_by(current_stage='filed').count()
            
            stats = {
                'total_pors': total_pors,
                'received': received_count,
                'sent': sent_count,
                'filed': filed_count,
                'company': self.company_name.upper(),
                'database_file': self.config.database_file
            }
            
            logger.info(f"📊 {self.company_name.upper()}: Statistics - Total: {total_pors}, Received: {received_count}, Sent: {sent_count}, Filed: {filed_count}")
            return stats
            
        except Exception as e:
            logger.error(f"❌ {self.company_name.upper()}: Error getting statistics: {e}")
            return {'error': str(e)}
        finally:
            session.close()


class APPORApp(IndependentPORApp):
    """A&P POR Application - Completely Independent."""
    
    def __init__(self):
        super().__init__('a&p')
        self.display_name = "A&P POR System"
        self.theme_color = "blue"
    
    def check_business_rules(self, por_data):
        """A&P specific business rules."""
        warnings = []
        
        # Check for FDEC job numbers in A&P database
        fdec_warning = self.config.check_fdec_warning(por_data.get('job_contract_no'))
        if fdec_warning:
            warnings.append(fdec_warning)
        
        # A&P specific validation rules
        if por_data.get('order_total', 0) > 50000:
            warnings.append("⚠️ High value order - requires additional approval")
        
        return warnings


class FDECPORApp(IndependentPORApp):
    """FDEC POR Application - Completely Independent."""
    
    def __init__(self):
        super().__init__('fdec')
        self.display_name = "FDEC POR System"
        self.theme_color = "green"
    
    def check_business_rules(self, por_data):
        """FDEC specific business rules."""
        warnings = []
        
        # FDEC specific validation rules
        if not por_data.get('job_contract_no'):
            warnings.append("⚠️ Job contract number is required for FDEC orders")
        
        if por_data.get('content_type') != 'work_iwo':
            warnings.append("ℹ️ Most FDEC orders are work_iwo type")
        
        return warnings


# Create independent application instances
ap_app = APPORApp()
fdec_app = FDECPORApp()


def get_app_for_company(company_name):
    """Get the appropriate application instance for a company."""
    if company_name == 'a&p':
        return ap_app
    elif company_name == 'fdec':
        return fdec_app
    else:
        raise ValueError(f"Unknown company: {company_name}")


# Convenience functions for direct access
def get_ap_app():
    """Get A&P application instance."""
    return ap_app


def get_fdec_app():
    """Get FDEC application instance."""
    return fdec_app


# Example usage functions
def work_with_ap_only():
    """Example: Work with A&P database only - no impact on FDEC."""
    app = get_ap_app()
    
    # Get A&P statistics
    stats = app.get_statistics()
    print(f"A&P Database Stats: {stats}")
    
    # Get A&P PORs
    pors = app.get_por_list()
    print(f"A&P has {len(pors)} PORs")
    
    return app


def work_with_fdec_only():
    """Example: Work with FDEC database only - no impact on A&P."""
    app = get_fdec_app()
    
    # Get FDEC statistics
    stats = app.get_statistics()
    print(f"FDEC Database Stats: {stats}")
    
    # Get FDEC PORs
    pors = app.get_por_list()
    print(f"FDEC has {len(pors)} PORs")
    
    return app


if __name__ == "__main__":
    # Test independent operation
    print("🧪 Testing independent database operations...")
    
    print("\n📊 A&P Operations (isolated):")
    ap_app = work_with_ap_only()
    
    print("\n📊 FDEC Operations (isolated):")
    fdec_app = work_with_fdec_only()
    
    print("\n✅ Both companies operating independently!")
