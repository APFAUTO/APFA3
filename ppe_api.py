
import sqlite3
import io
import csv
from flask import Blueprint, jsonify, request, Response

ppe_api = Blueprint('ppe_api', __name__, url_prefix='/api/ppe')

def get_db_connection():
    conn = sqlite3.connect('ppe_reporting.db')
    conn.row_factory = sqlite3.Row
    return conn

@ppe_api.route('/entry', methods=['POST'])
def add_ppe_entry():
    """Add new PPE usage entries."""
    conn = get_db_connection()
    c = conn.cursor()
    
    data = request.get_json()
    
    employee_id = data.get('employee_id')
    employee_name = data.get('employee_name')
    department = data.get('department')
    date_str = data.get('date')
    items = data.get('items', [])
    
    if not all([employee_id, employee_name, department, date_str, items]):
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
    try:
        entry_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        week = entry_date.isocalendar()[1]
        month = entry_date.month
        year = entry_date.year
        
        inserted_records = 0
        for item in items:
            ppe_item = item.get('ppe_item')
            quantity = item.get('quantity')
            
            if not all([ppe_item, quantity]):
                continue
            
            c.execute("""
                INSERT INTO ppe_usage (
                    date, employee_id, employee_name, department, 
                    ppe_item, quantity, checkout_time, week, month, year
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                date_str, employee_id, employee_name, department,
                ppe_item, quantity, datetime.now().isoformat(), week, month, year
            ))
            inserted_records += 1
            
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'inserted_records': inserted_records,
            'timestamp': datetime.now().isoformat()
        }), 201
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@ppe_api.route('/employees/search', methods=['GET'])
def search_employees():
    conn = get_db_connection()
    c = conn.cursor()
    query = request.args.get('query', '').lower()
    department = request.args.get('department', '')

    sql_query = "SELECT DISTINCT employee_id, employee_name, department FROM ppe_usage WHERE 1=1"
    params = []

    if query:
        sql_query += " AND (LOWER(employee_name) LIKE ? OR LOWER(employee_id) LIKE ?)"
        params.append(f'%{query}%')
        params.append(f'%{query}%')
    
    if department:
        sql_query += " AND department = ?"
        params.append(department)

    c.execute(sql_query, params)
    employees = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(employees)

@ppe_api.route('/items/search', methods=['GET'])
def search_ppe_items():
    conn = get_db_connection()
    c = conn.cursor()
    query = request.args.get('query', '').lower()

    sql_query = "SELECT DISTINCT ppe_item FROM ppe_usage WHERE LOWER(ppe_item) LIKE ?"
    params = [f'%{query}%']

    c.execute(sql_query, params)
    ppe_items = [row['ppe_item'] for row in c.fetchall()]
    conn.close()
    return jsonify(ppe_items)

@ppe_api.route('/usage', methods=['GET'])
def get_usage_data():
    """Get PPE usage data with optional filtering."""
    conn = get_db_connection()
    c = conn.cursor()

    # Base query
    query = "SELECT * FROM ppe_usage"

    # Filtering
    filters = []
    params = []

    department = request.args.get('department')
    if department:
        filters.append("department IN (%s)" % ",".join("?"*len(department.split(','))))
        params.extend(department.split(','))

    ppe_item = request.args.get('ppe_item')
    if ppe_item:
        filters.append("ppe_item IN (%s)" % ",".join("?"*len(ppe_item.split(','))))
        params.extend(ppe_item.split(','))

    employee_id = request.args.get('employee_id')
    if employee_id:
        filters.append("employee_id = ?")
        params.append(employee_id)

    start_date = request.args.get('start_date')
    if start_date:
        filters.append("date >= ?")
        params.append(start_date)

    end_date = request.args.get('end_date')
    if end_date:
        filters.append("date <= ?")
        params.append(end_date)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    c.execute(query, params)
    data = [dict(row) for row in c.fetchall()]
    conn.close()

    return jsonify(data)

@ppe_api.route('/filters', methods=['GET'])
def get_filter_options():
    """Get distinct values for filters."""
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT DISTINCT department FROM ppe_usage")
    departments = [row['department'] for row in c.fetchall()]

    c.execute("SELECT DISTINCT ppe_item FROM ppe_usage")
    ppe_items = [row['ppe_item'] for row in c.fetchall()]

    c.execute("SELECT DISTINCT employee_id, employee_name, COALESCE(department, 'Unknown') as department FROM ppe_usage")
    employees = [dict(row) for row in c.fetchall()]

    conn.close()

    return jsonify({
        'departments': departments,
        'ppe_items': ppe_items,
        'employees': employees
    })

@ppe_api.route('/export/csv', methods=['GET'])
def export_csv():
    """Export PPE usage data to a CSV file."""
    conn = get_db_connection()
    c = conn.cursor()

    # Base query
    query = "SELECT * FROM ppe_usage"

    # Filtering
    filters = []
    params = []

    department = request.args.get('department')
    if department:
        filters.append("department IN (%s)" % ",".join("?"*len(department.split(','))))
        params.extend(department.split(','))

    ppe_item = request.args.get('ppe_item')
    if ppe_item:
        filters.append("ppe_item IN (%s)" % ",".join("?"*len(ppe_item.split(','))))
        params.extend(ppe_item.split(','))

    employee_id = request.args.get('employee_id')
    if employee_id:
        filters.append("employee_id = ?")
        params.append(employee_id)

    start_date = request.args.get('start_date')
    if start_date:
        filters.append("date >= ?")
        params.append(start_date)

    end_date = request.args.get('end_date')
    if end_date:
        filters.append("date <= ?")
        params.append(end_date)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    c.execute(query, params)
    data = c.fetchall()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([description[0] for description in c.description])

    # Write data
    for row in data:
        writer.writerow(row)

    output.seek(0)
    conn.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=ppe_usage.csv"}
    )
