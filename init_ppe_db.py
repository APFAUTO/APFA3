
import sqlite3

def create_ppe_database():
    """Create the PPE reporting database and the ppe_usage table."""
    try:
        conn = sqlite3.connect('ppe_reporting.db')
        c = conn.cursor()

        # Create ppe_usage table
        c.execute('''
            CREATE TABLE IF NOT EXISTS ppe_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE,
                employee_id TEXT,
                employee_name TEXT,
                department TEXT,
                ppe_item TEXT,
                quantity INTEGER,
                checkout_time TIMESTAMP,
                return_time TIMESTAMP,
                duration_hours REAL,
                week INTEGER,
                month INTEGER,
                year INTEGER
            )
        ''')

        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_date ON ppe_usage(date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_department ON ppe_usage(department)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_employee ON ppe_usage(employee_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ppe_item ON ppe_usage(ppe_item)')

        conn.commit()
        print("Successfully created ppe_reporting.db and ppe_usage table.")

    except sqlite3.Error as e:
        print(f"Error creating PPE database: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_ppe_database()
