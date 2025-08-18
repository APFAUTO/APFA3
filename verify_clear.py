import sqlite3
import os

def check_database(db_file, company_name):
    """Check database status after clearing."""
    if not os.path.exists(db_file):
        print(f"❌ {db_file} not found")
        return
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    print(f"📊 {company_name} Database ({db_file}):")
    
    # Check POR records
    cursor.execute("SELECT COUNT(*) FROM por")
    por_count = cursor.fetchone()[0]
    print(f"  - POR records: {por_count}")
    
    # Check batch counter
    try:
        cursor.execute("SELECT value FROM batch_counter LIMIT 1")
        counter = cursor.fetchone()
        if counter:
            print(f"  - Batch counter: {counter[0]}")
        else:
            print("  - Batch counter: Not set")
    except Exception as e:
        print(f"  - Batch counter: Error - {e}")
    
    conn.close()
    print()

print("🔍 Database Status Verification")
print("=" * 40)
check_database('a&p_por.db', 'A&P')
check_database('fdec_por.db', 'FDEC')
print("✅ Verification complete!")
