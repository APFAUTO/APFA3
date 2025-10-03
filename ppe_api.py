
import sqlite3
import io
import csv
from flask import Blueprint, jsonify, request, Response

ppe_api = Blueprint('ppe_api', __name__, url_prefix='/api/ppe')

def get_db_connection():
    conn = sqlite3.connect('ppe_reporting.db')
    conn.row_factory = sqlite3.Row
    return conn

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

    c.execute("SELECT DISTINCT employee_id, employee_name FROM ppe_usage")
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
