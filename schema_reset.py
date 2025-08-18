#!/usr/bin/env python3
"""
Schema-aware database reset script.
"""

import os
import sqlite3

def get_table_names(db_path):
    """Get all table names from a database."""
    if not os.path.exists(db_path):
        return []
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    return tables

def reset_database(db_path, company_name):
    """Reset a single database."""
    if not os.path.exists(db_path):
        print(f"⚠️  Database {db_path} not found")
        return
    
    print(f"🔄 Resetting {company_name} database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    tables = get_table_names(db_path)
    print(f"📋 Found tables: {tables}")
    
    # Get current record counts
    record_counts = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            record_counts[table] = count
        except Exception as e:
            record_counts[table] = f"Error: {e}"
    
    print(f"📊 Current record counts: {record_counts}")
    
    # Clear all tables (order matters due to foreign keys)
    tables_to_clear = []
    
    # Determine clearing order based on likely foreign key dependencies
    if 'line_items' in tables:
        tables_to_clear.append('line_items')
    elif 'lineitems' in tables:
        tables_to_clear.append('lineitems')
    elif 'lineitem' in tables:
        tables_to_clear.append('lineitem')
    
    if 'por_files' in tables:
        tables_to_clear.append('por_files')
    elif 'porfiles' in tables:
        tables_to_clear.append('porfiles')
    elif 'por_file' in tables:
        tables_to_clear.append('por_file')
    
    if 'por' in tables:
        tables_to_clear.append('por')
    elif 'pors' in tables:
        tables_to_clear.append('pors')
    
    if 'batch_counter' in tables:
        tables_to_clear.append('batch_counter')
    elif 'batch_counters' in tables:
        tables_to_clear.append('batch_counters')
    
    # Add any remaining tables
    for table in tables:
        if table not in tables_to_clear:
            tables_to_clear.append(table)
    
    print(f"🗑️  Clearing tables in order: {tables_to_clear}")
    
    # Clear tables
    for table in tables_to_clear:
        try:
            cursor.execute(f"DELETE FROM {table}")
            print(f"   ✅ Cleared {table}")
        except Exception as e:
            print(f"   ⚠️  Could not clear {table}: {e}")
    
    # Insert new batch counter
    batch_table = None
    if 'batch_counter' in tables:
        batch_table = 'batch_counter'
    elif 'batch_counters' in tables:
        batch_table = 'batch_counters'
    
    if batch_table:
        try:
            cursor.execute(f"INSERT INTO {batch_table} (company, current_batch) VALUES (?, 0)", (company_name,))
            print(f"   ✅ Set batch counter to 0 in {batch_table}")
        except Exception as e:
            print(f"   ⚠️  Could not set batch counter: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"✅ {company_name} database reset completed")

def main():
    """Main reset function."""
    print("🔄 Starting database reset to zero...")
    print("=" * 50)
    
    # Reset A&P database
    reset_database("a&p_por.db", "a&p")
    print()
    
    # Reset FDEC database  
    reset_database("fdec_por.db", "fdec")
    print()
    
    # Final verification
    print("🔍 Final Verification...")
    print("-" * 30)
    
    for db_path, company in [("a&p_por.db", "A&P"), ("fdec_por.db", "FDEC")]:
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check POR count
            try:
                cursor.execute("SELECT COUNT(*) FROM por")
                por_count = cursor.fetchone()[0]
            except:
                por_count = "N/A"
            
            # Check batch counter
            try:
                cursor.execute("SELECT current_batch FROM batch_counter WHERE company = ?", (company.lower().replace('&', '&'),))
                batch_result = cursor.fetchone()
                batch_count = batch_result[0] if batch_result else "NOT FOUND"
            except:
                batch_count = "N/A"
            
            conn.close()
            print(f"📊 {company}: {por_count} PORs, Batch: {batch_count}")
    
    print("\n🎉 Reset to zero completed!")

if __name__ == "__main__":
    main()
