#!/usr/bin/env python3
"""
Reset both A&P and FDEC databases to completely empty state with batch counters at 0.
This script will:
1. Clear all POR records from both databases
2. Clear all line items from both databases  
3. Clear all POR files from both databases
4. Reset batch counters to 0 for both companies
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database_managers import APDatabaseManager, FDECDatabaseManager
from batch_number_manager import BatchNumberManager
from company_config import APConfig, FDECConfig

def reset_database_to_zero():
    """Reset both databases to completely empty state with counters at 0."""
    
    print("🔄 Starting complete database reset to zero...")
    print("=" * 60)
    
    # Initialize database managers
    ap_db = APDatabaseManager()
    fdec_db = FDECDatabaseManager()
    
    try:
        # Reset A&P Database
        print("\n📊 Resetting A&P Database...")
        print("-" * 30)
        
        ap_session = ap_db.get_session()
        
        # Get counts before deletion
        ap_por_count = ap_session.query(ap_db.POR).count()
        ap_line_count = ap_session.query(ap_db.LineItem).count()
        ap_file_count = ap_session.query(ap_db.PORFile).count()
        
        print(f"📋 Current A&P records:")
        print(f"   - PORs: {ap_por_count}")
        print(f"   - Line Items: {ap_line_count}")
        print(f"   - Files: {ap_file_count}")
        
        # Delete all records
        ap_session.query(ap_db.LineItem).delete()
        ap_session.query(ap_db.PORFile).delete()
        ap_session.query(ap_db.POR).delete()
        
        # Reset batch counter to 0
        ap_session.query(ap_db.BatchCounter).delete()
        new_counter = ap_db.BatchCounter(company='a&p', current_batch=0)
        ap_session.add(new_counter)
        
        ap_session.commit()
        ap_session.close()
        
        print("✅ A&P database cleared and counter reset to 0")
        
        # Reset FDEC Database
        print("\n📊 Resetting FDEC Database...")
        print("-" * 30)
        
        fdec_session = fdec_db.get_session()
        
        # Get counts before deletion
        fdec_por_count = fdec_session.query(fdec_db.POR).count()
        fdec_line_count = fdec_session.query(fdec_db.LineItem).count()
        fdec_file_count = fdec_session.query(fdec_db.PORFile).count()
        
        print(f"📋 Current FDEC records:")
        print(f"   - PORs: {fdec_por_count}")
        print(f"   - Line Items: {fdec_line_count}")
        print(f"   - Files: {fdec_file_count}")
        
        # Delete all records
        fdec_session.query(fdec_db.LineItem).delete()
        fdec_session.query(fdec_db.PORFile).delete()
        fdec_session.query(fdec_db.POR).delete()
        
        # Reset batch counter to 0
        fdec_session.query(fdec_db.BatchCounter).delete()
        new_counter = fdec_db.BatchCounter(company='fdec', current_batch=0)
        fdec_session.add(new_counter)
        
        fdec_session.commit()
        fdec_session.close()
        
        print("✅ FDEC database cleared and counter reset to 0")
        
        # Initialize batch number managers and reset to 0
        print("\n🔢 Resetting Batch Number Managers...")
        print("-" * 30)
        
        # Reset A&P batch manager
        ap_batch_manager = BatchNumberManager('a&p')
        ap_batch_manager.reset_to_start()
        ap_batch_manager.set_batch_number(0)
        
        # Reset FDEC batch manager  
        fdec_batch_manager = BatchNumberManager('fdec')
        fdec_batch_manager.reset_to_start()
        fdec_batch_manager.set_batch_number(0)
        
        print("✅ A&P batch counter set to 0")
        print("✅ FDEC batch counter set to 0")
        
        # Verify the reset
        print("\n🔍 Verification...")
        print("-" * 30)
        
        # Verify A&P
        ap_session = ap_db.get_session()
        ap_por_final = ap_session.query(ap_db.POR).count()
        ap_batch_final = ap_batch_manager.get_current_batch_number()
        ap_session.close()
        
        # Verify FDEC
        fdec_session = fdec_db.get_session()
        fdec_por_final = fdec_session.query(fdec_db.POR).count()
        fdec_batch_final = fdec_batch_manager.get_current_batch_number()
        fdec_session.close()
        
        print(f"📊 Final state:")
        print(f"   A&P: {ap_por_final} PORs, Batch counter: {ap_batch_final}")
        print(f"   FDEC: {fdec_por_final} PORs, Batch counter: {fdec_batch_final}")
        
        print("\n🎉 Database reset to zero completed successfully!")
        print("=" * 60)
        print("Both databases are now completely empty with batch counters at 0.")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error during database reset: {str(e)}")
        print("Rolling back any partial changes...")
        
        try:
            if 'ap_session' in locals():
                ap_session.rollback()
                ap_session.close()
        except:
            pass
            
        try:
            if 'fdec_session' in locals():
                fdec_session.rollback()
                fdec_session.close()
        except:
            pass
        
        return False

if __name__ == "__main__":
    print("⚠️  WARNING: This will completely empty both A&P and FDEC databases!")
    print("All POR records, line items, and files will be permanently deleted.")
    print("Batch counters will be reset to 0.")
    print()
    
    confirm = input("Are you sure you want to proceed? (type 'YES' to confirm): ")
    
    if confirm == "YES":
        success = reset_database_to_zero()
        if success:
            print("\n✅ Reset completed successfully!")
        else:
            print("\n❌ Reset failed. Check the error messages above.")
    else:
        print("❌ Reset cancelled.")
