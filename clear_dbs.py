import sqlite3
import os

def clear_database(db_file, company_name, batch_start):
    """Clear database and reset counter."""
    if not os.path.exists(db_file):
        print(f"❌ {db_file} not found")
        return
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Get counts before clearing
    try:
        cursor.execute("SELECT COUNT(*) FROM por")
        por_count = cursor.fetchone()[0]
        print(f"📊 {company_name}: {por_count} POR records found")
    except:
        por_count = 0
    
    # Clear all tables
    try:
        cursor.execute("DELETE FROM line_items")
        cursor.execute("DELETE FROM por_files") 
        cursor.execute("DELETE FROM por")
        cursor.execute("DELETE FROM batch_counter")
        cursor.execute("INSERT INTO batch_counter (id, value) VALUES (1, ?)", (batch_start,))
        conn.commit()
        print(f"✅ {company_name} database cleared, counter reset to {batch_start}")
    except Exception as e:
        print(f"❌ Error clearing {company_name}: {e}")
    
    conn.close()

# Clear both databases
print("🧹 Clearing both databases...")
clear_database('a&p_por.db', 'A&P', 5000)
clear_database('fdec_por.db', 'FDEC', 6000)
print("✅ Both databases cleared and counters reset!")
