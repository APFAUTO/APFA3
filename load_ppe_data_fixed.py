import pandas as pd
import sqlite3
import json
from pathlib import Path

def load_ppe_data():
    # Paths
    db_path = Path(r'c:\Users\wesle\Documents\FIX-4.1\ppe_reporting.db')
    csv_path = Path(r'c:\Users\wesle\Documents\FIX-4.1\ppelogger\Copy of WEEKLY PPE AUGUST 2025 (002).csv')
    
    print("Reading CSV file...")
    # Read the CSV, skip the second row which contains item codes
    df = pd.read_csv(csv_path, skiprows=[1])
    
    # Rename columns for consistency
    df = df.rename(columns={
        'Employee Id': 'employee_id',
        'Known As': 'known_as',
        'Surname': 'surname',
        'Department': 'department'
    })
    
    # Get list of PPE item columns (all columns except the ID and name columns)
    ppe_columns = [col for col in df.columns if col not in ['employee_id', 'known_as', 'surname', 'department']]
    
    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ppe_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id TEXT,
        known_as TEXT,
        surname TEXT,
        department TEXT,
        date TEXT,
        items TEXT
    )
    ''')
    
    # Clear existing data
    cursor.execute('DELETE FROM ppe_entries')
    
    print("Processing data and inserting into database...")
    # Process each row
    for _, row in df.iterrows():
        # Create items dictionary for non-zero quantities
        items = {}
        for col in ppe_columns:
            quantity = int(row[col])
            if pd.notna(quantity) and quantity > 0:
                items[col] = quantity
        
        # Only insert if there are items
        if items:
            cursor.execute('''
            INSERT INTO ppe_entries 
            (employee_id, known_as, surname, department, date, items)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                row['employee_id'],
                row['known_as'],
                row['surname'],
                row['department'],
                '2025-08-01',  # Date from filename
                json.dumps(items)
            ))
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Successfully loaded data into {db_path}")

if __name__ == "__main__":
    load_ppe_data()
