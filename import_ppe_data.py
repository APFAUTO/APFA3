
import sqlite3
import csv
from datetime import datetime

def import_ppe_data(csv_file_path):
    """Import PPE data from a CSV file into the ppe_reporting.db database."""
    try:
        conn = sqlite3.connect('ppe_reporting.db')
        c = conn.cursor()

        with open(csv_file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            header = next(reader) # Skip the header row
            ppe_items = header[4:] # Get the PPE item names

            # Skip the second header row
            next(reader)

            for row in reader:
                employee_id = row[0]
                employee_name = f'{row[1]} {row[2]}'
                department = row[3]

                for i, quantity_str in enumerate(row[4:]):
                    quantity = int(quantity_str)
                    if quantity > 0:
                        ppe_item = ppe_items[i]
                        # I will need to get the date from the filename or assume the current date.
                        # For now, I will use a placeholder date.
                        date_str = '2025-08-01'
                        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
                        week = date_obj.isocalendar()[1]
                        month = date_obj.month
                        year = date_obj.year

                        c.execute('''
                            INSERT INTO ppe_usage (date, employee_id, employee_name, department, ppe_item, quantity, week, month, year)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (date_obj, employee_id, employee_name, department, ppe_item, quantity, week, month, year))

        conn.commit()
        print(f"Successfully imported data from {csv_file_path} into ppe_reporting.db")

    except sqlite3.Error as e:
        print(f"Error importing PPE data: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    import_ppe_data('ppelogger/Copy of WEEKLY PPE AUGUST 2025 (002).csv')
