#!/usr/bin/env python3
"""
Simple script to reset both databases to zero without prompts.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database_managers import APDatabaseManager, FDECDatabaseManager
from batch_number_manager import BatchNumberManager

def reset_databases():
    """Reset both databases to zero."""
    
    print("Resetting A&P Database...")
    
    # Reset A&P
    ap_db = APDatabaseManager()
    ap_session = ap_db.get_session()
    
    # Clear all A&P records
    ap_session.query(ap_db.LineItem).delete()
    ap_session.query(ap_db.PORFile).delete()
    ap_session.query(ap_db.POR).delete()
    ap_session.query(ap_db.BatchCounter).delete()
    
    # Add new counter at 0
    new_counter = ap_db.BatchCounter(company='a&p', current_batch=0)
    ap_session.add(new_counter)
    ap_session.commit()
    ap_session.close()
    
    print("A&P database cleared and counter set to 0")
    
    print("Resetting FDEC Database...")
    
    # Reset FDEC
    fdec_db = FDECDatabaseManager()
    fdec_session = fdec_db.get_session()
    
    # Clear all FDEC records
    fdec_session.query(fdec_db.LineItem).delete()
    fdec_session.query(fdec_db.PORFile).delete()
    fdec_session.query(fdec_db.POR).delete()
    fdec_session.query(fdec_db.BatchCounter).delete()
    
    # Add new counter at 0
    new_counter = fdec_db.BatchCounter(company='fdec', current_batch=0)
    fdec_session.add(new_counter)
    fdec_session.commit()
    fdec_session.close()
    
    print("FDEC database cleared and counter set to 0")
    
    # Reset batch managers using convenience functions
    print("Resetting batch managers...")
    
    try:
        from batch_number_manager import get_batch_manager
        
        ap_batch = get_batch_manager('a&p')
        ap_batch.set_batch_number(0)
        
        fdec_batch = get_batch_manager('fdec')
        fdec_batch.set_batch_number(0)
        
        print("Both batch managers reset to 0")
    except Exception as e:
        print(f"Note: Batch manager reset may need manual verification: {e}")
    print("Reset completed successfully!")

if __name__ == "__main__":
    reset_databases()
