"""
Database Reset Script - Clear all data and reset counters for both companies.
This will completely wipe both A&P and FDEC databases and reset PO counters.
"""

import sqlite3
import os
from config import COMPANIES

def clear_database(db_file, company_name):
    """Clear all data from a database and reset counters."""
    if not os.path.exists(db_file):
        print(f"❌ Database {db_file} does not exist")
        return False
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Get current record counts before clearing
        cursor.execute("SELECT COUNT(*) FROM por")
        por_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM por_files")
        files_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM line_items")
        items_count = cursor.fetchone()[0]
        
        print(f"📊 {company_name.upper()} Database ({db_file}):")
        print(f"  - POR records: {por_count}")
        print(f"  - File records: {files_count}")
        print(f"  - Line items: {items_count}")
        
        # Clear all tables
        cursor.execute("DELETE FROM line_items")
        cursor.execute("DELETE FROM por_files")
        cursor.execute("DELETE FROM por")
        
        # Reset batch counter
        batch_start = COMPANIES.get(company_name, {}).get('batch_start', 5000)
        cursor.execute("DELETE FROM batch_counter")
        cursor.execute("INSERT INTO batch_counter (id, value) VALUES (1, ?)", (batch_start,))
        
        conn.commit()
        conn.close()
        
        print(f"✅ {company_name.upper()} database cleared successfully")
        print(f"🔄 PO counter reset to {batch_start}")
        return True
        
    except Exception as e:
        print(f"❌ Error clearing {company_name} database: {e}")
        return False

def main():
    """Clear both databases and reset counters."""
    print("🧹 Database Reset Script")
    print("=" * 50)
    print("⚠️  WARNING: This will permanently delete ALL data!")
    print("=" * 50)
    
    # Confirm action
    confirm = input("Are you sure you want to clear both databases? (yes/no): ").lower().strip()
    if confirm != 'yes':
        print("❌ Operation cancelled")
        return
    
    print("\n🗑️  Clearing databases...")
    
    # Clear A&P database
    ap_success = clear_database('a&p_por.db', 'a&p')
    
    # Clear FDEC database  
    fdec_success = clear_database('fdec_por.db', 'fdec')
    
    print("\n" + "=" * 50)
    if ap_success and fdec_success:
        print("✅ Both databases cleared successfully!")
        print("🔄 All PO counters reset to starting values")
        print("🎯 Ready for fresh data entry")
    else:
        print("❌ Some operations failed - check errors above")
    print("=" * 50)

if __name__ == "__main__":
    main()
