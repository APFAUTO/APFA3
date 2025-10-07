#!/usr/bin/env python3
"""Initialize a simple PPE reporting SQLite database from the provided CSV.

Creates a table `ppe_entries` with columns:
- id (autoincrement)
- employee_id
- known_as
- surname
- department
- items (JSON text mapping item name -> integer)
- date (text)

This is intentionally simple and temporary for reporting/testing.
"""
import csv
import json
import sqlite3
from pathlib import Path

WORKDIR = Path(__file__).resolve().parents[1]
CSV_PATH = WORKDIR / 'ppelogger' / 'Copy of WEEKLY PPE AUGUST 2025 (002).csv'
DB_PATH = WORKDIR / 'ppe_reporting.db'

print(f"CSV: {CSV_PATH}")
print(f"DB:  {DB_PATH}")

if not CSV_PATH.exists():
    print("CSV file not found. Exiting.")
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute('''
CREATE TABLE IF NOT EXISTS ppe_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT,
    known_as TEXT,
    surname TEXT,
    department TEXT,
    items TEXT,
    date TEXT
)
''')
conn.commit()

inserted = 0
with CSV_PATH.open(newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        emp = (row.get('Employee Id') or '').strip()
        known = (row.get('Known As') or '').strip()
        surname = (row.get('Surname') or '').strip()
        dept = (row.get('Department') or '').strip()

        # Skip empty header or blank rows
        if not emp:
            continue

        # Build items map (everything except core columns)
        items = {}
        for k, v in row.items():
            if k in ('Employee Id', 'Known As', 'Surname', 'Department'):
                continue
            # Attempt integer parse, else zero
            try:
                items[k] = int(v) if v is not None and v != '' else 0
            except ValueError:
                try:
                    items[k] = int(float(v))
                except Exception:
                    items[k] = 0

        # Use a placeholder date if no Date field
        date = row.get('Date') or '2025-08-01'

        cur.execute('INSERT INTO ppe_entries (employee_id, known_as, surname, department, items, date) VALUES (?, ?, ?, ?, ?, ?)',
                    (emp, known, surname, dept, json.dumps(items), date))
        inserted += 1

conn.commit()
print(f"Inserted {inserted} rows into {DB_PATH}")

# Quick sample
cur.execute('SELECT COUNT(* ) FROM ppe_entries')
count = cur.fetchone()[0]
print('Row count:', count)
cur.execute('SELECT id, employee_id, known_as, surname, department, items FROM ppe_entries LIMIT 3')
for r in cur.fetchall():
    print(r)

conn.close()
