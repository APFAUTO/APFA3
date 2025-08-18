#!/usr/bin/env python3
"""
Direct database reset - bypasses batch manager issues.
"""

import os
import sys
import sqlite3

def reset_databases_direct():
    """Reset both databases directly using SQLite commands."""
    
    # Database file paths
    ap_db_path = "a&p_por.db"
    fdec_db_path = "fdec_por.db"
    
    print("🔄 Resetting A&P Database...")
    
    # Reset A&P database
    if os.path.exists(ap_db_path):
        conn = sqlite3.connect(ap_db_path)
        cursor = conn.cursor()
        
        # Get current counts
        cursor.execute("SELECT COUNT(*) FROM por")
        ap_por_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM line_item")
        ap_line_count = cursor.fetchone()[0]
        
        print(f"📊 A&P before reset: {ap_por_count} PORs, {ap_line_count} line items")
        
        # Clear all tables
        cursor.execute("DELETE FROM line_item")
        cursor.execute("DELETE FROM por_file")
        cursor.execute("DELETE FROM por")
        cursor.execute("DELETE FROM batch_counter")
        
        # Insert new batch counter at 0
        cursor.execute("INSERT INTO batch_counter (company, current_batch) VALUES ('a&p', 0)")
        
        conn.commit()
        conn.close()
        
        print("✅ A&P database cleared and counter set to 0")
    else:
        print("⚠️  A&P database file not found")
    
    print("🔄 Resetting FDEC Database...")
    
    # Reset FDEC database
    if os.path.exists(fdec_db_path):
        conn = sqlite3.connect(fdec_db_path)
        cursor = conn.cursor()
        
        # Get current counts
        cursor.execute("SELECT COUNT(*) FROM por")
        fdec_por_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM line_item")
        fdec_line_count = cursor.fetchone()[0]
        
        print(f"📊 FDEC before reset: {fdec_por_count} PORs, {fdec_line_count} line items")
        
        # Clear all tables
        cursor.execute("DELETE FROM line_item")
        cursor.execute("DELETE FROM por_file")
        cursor.execute("DELETE FROM por")
        cursor.execute("DELETE FROM batch_counter")
        
        # Insert new batch counter at 0
        cursor.execute("INSERT INTO batch_counter (company, current_batch) VALUES ('fdec', 0)")
        
        conn.commit()
        conn.close()
        
        print("✅ FDEC database cleared and counter set to 0")
    else:
        print("⚠️  FDEC database file not found")
    
    # Verify the reset
    print("\n🔍 Verification...")
    
    # Verify A&P
    if os.path.exists(ap_db_path):
        conn = sqlite3.connect(ap_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM por")
        ap_final_por = cursor.fetchone()[0]
        cursor.execute("SELECT current_batch FROM batch_counter WHERE company = 'a&p'")
        ap_batch = cursor.fetchone()
        ap_batch_value = ap_batch[0] if ap_batch else "NOT FOUND"
        conn.close()
        print(f"📊 A&P final: {ap_final_por} PORs, batch counter: {ap_batch_value}")
    
    # Verify FDEC
    if os.path.exists(fdec_db_path):
        conn = sqlite3.connect(fdec_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM por")
        fdec_final_por = cursor.fetchone()[0]
        cursor.execute("SELECT current_batch FROM batch_counter WHERE company = 'fdec'")
        fdec_batch = cursor.fetchone()
        fdec_batch_value = fdec_batch[0] if fdec_batch else "NOT FOUND"
        conn.close()
        print(f"📊 FDEC final: {fdec_final_por} PORs, batch counter: {fdec_batch_value}")
    
    print("\n🎉 Database reset completed!")
    print("Both databases are now empty with batch counters at 0.")

if __name__ == "__main__":
    reset_databases_direct()
