import os
import logging

# Setup logging
logger = logging.getLogger(__name__)

import json
from datetime import datetime, timezone
from typing import Optional, Tuple, List

from flask import Blueprint, request, render_template, flash, redirect, url_for, send_file, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import func

from database import save_por_to_database, get_paginated_records, get_current_database
from file_processing import process_uploaded_file
from utils import (
    allowed_file,
    allowed_excel_file,
    get_file_type_icon,
    capitalize_text,
    clean_query_string,
    get_company_info,
    add_change_to_history,
    undo_last_change,
    redo_last_change,
)
from auth.security import login_required
from database_managers import get_database_manager
from company_config import get_company_config

routes = Blueprint('routes', __name__, url_prefix='/')

@routes.route('/test')
def test():
    """Test route for debugging database and system status."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        # Check database status
        total_records = db_session.query(db_manager.POR).count()
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po = counter.value if counter else 'No counter found'
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(db_manager.engine)
        tables = inspector.get_table_names()
        
        db_session.close()
        
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Status</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
                .success { background-color: #d4edda; color: #155724; }
                .error { background-color: #f8d7da; color: #721c24; }
                .info { background-color: #d1ecf1; color: #0c5460; }
            </style>
        </head>
        <body>
            <h1>🔍 System Status Check</h1>
            
            <div class="status success">
                <h3>✅ Database Connection</h3>
                <p>Database URL: %s</p>
                <p>Tables found: %s</p>
            </div>
            
            <div class="status info">
                <h3>📊 Data Status</h3>
                <p>Total POR records: %s</p>
                <p>Current PO number: %s</p>
            </div>
            
            <div class="status info">
                <h3>🔗 Navigation</h3>
                <p><a href="/">📤 Upload Page</a></p>
                <p><a href="/view">👁️ View Records</a></p>
                <p><a href="/search">🔍 Search</a></p>
                <p><a href="/change-batch">🔄 Batch Change</a></p>
                <p><a href="/dashboard">📊 Dashboard</a></p>
            </div>
            
            <div class="status info">
                <h3>🧪 Test Upload</h3>
                <p><a href="/debug-upload">🔬 Debug Upload Test</a></p>
            </div>
        </body>
        </html>
        ''' % (db_manager.database_url, ', '.join(tables) if tables else 'None', total_records, current_po)
    except Exception as e:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Error</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .error { background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>❌ System Error</h1>
            <div class="error">
                <p><strong>Error:</strong> %s</p>
                <p>This indicates a database connection or initialization problem.</p>
            </div>
        </body>
        </html>
        ''' % str(e)


@routes.route('/debug-upload', methods=['GET', 'POST'])
def debug_upload():
    """Debug route to test file upload functionality."""
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if file:
                logger.info(f"DEBUG: File received - {file.filename}")
                logger.info(f"DEBUG: File type - {getattr(file, 'content_type', 'unknown')}")
                
                # Test file validation
                is_allowed = allowed_excel_file(file.filename)
                logger.info(f"DEBUG: File allowed for Excel uploader - {is_allowed}")
                
                # Test file content
                file.seek(0)
                first_bytes = file.read(8)
                file.seek(0)
                logger.info(f"DEBUG: File header - {first_bytes}")
                
                return {
                    'filename': file.filename,
                    'content_type': getattr(file, 'content_type', 'unknown'),
                    'allowed': is_allowed,
                    'header': str(first_bytes),
                    'size': len(first_bytes)
                }
            else:
                return {'error': 'No file received'}
        except Exception as e:
            return {'error': str(e)}
    
    return '''
    <html>
    <body>
        <h2>Debug Upload Test (Excel Only)</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xlsx,.xls">
            <input type="submit" value="Test Upload">
        </form>
    </body>
    </html>
    '''


@routes.route('/dashboard')
@login_required
def dashboard():
    """Display the main dashboard."""
    try:
        # Use database-aware session
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        # Get current PO from database
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po_value = counter.value if counter else 1000
        
        # Get some basic stats
        total_por_count = db_session.query(db_manager.POR).count()
        
        # Get company distribution stats
        a_and_p_count = db_session.query(db_manager.POR).filter(db_manager.POR.supplier == 'a&p').count()
        fdec_count = db_session.query(db_manager.POR).filter(db_manager.POR.supplier == 'FDEC').count()
        
        # Get recent activity (last 5 PORs)
        recent_activity = db_session.query(db_manager.POR).order_by(db_manager.POR.created_at.desc()).limit(5).all()
        
        db_session.close()
        
        # Get current database info for template
        company_info = get_company_config(current_db)
        
        return render_template("modern_dashboard.html", 
                             current_po=current_po_value,
                             total_por_count=total_por_count,
                             a_and_p_count=a_and_p_count,
                             fdec_count=fdec_count,
                             recent_activity=recent_activity,
                             company=current_db,
                             company_info=company_info,
                             active_page='dashboard')
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        # Get current database info for template
        current_db = get_current_database()
        company_info = get_company_config(current_db)
        
        return render_template("modern_dashboard.html", 
                             current_po=1000,
                             total_por_count=0,
                             a_and_p_count=0,
                             fdec_count=0,
                             recent_activity=[],
                             company=current_db,
                             company_info=company_info)



@routes.route('/switch-database/<database_name>')
def switch_database(database_name):
    """Switch between A&P and FDEC databases."""
    try:
        if database_name not in ['a&p', 'fdec']:
            flash("❌ Invalid database selection", 'error')
            return redirect(url_for('routes.dashboard'))
        
        # Update session with new database
        session['current_database'] = database_name
        logger.info(f"Switched to database: {database_name}")
        
        # Get company info for confirmation
        company_info = get_company_config(database_name)
        flash(f"✅ Switched to {company_info.display_name} database", 'success')
        
        return redirect(url_for('routes.dashboard'))
        
    except Exception as e:
        logger.error(f"Error switching database: {str(e)}")
        flash(f"❌ Error switching database: {str(e)}", 'error')
        return redirect(url_for('routes.dashboard'))


@routes.route('/switch_database', methods=['POST'])
def switch_database_api():
    """API endpoint for switching databases via AJAX."""
    try:
        data = request.get_json()
        database_name = data.get('database', '').lower()
        
        if database_name not in ['a&p', 'fdec']:
            return jsonify({'success': False, 'error': 'Invalid database selection'})
        
        # Update session with new database
        session['current_database'] = database_name
        logger.info(f"API switched to database: {database_name}")
        
        # Get company info and stats
        company_info = get_company_config(database_name)
        db_manager = get_database_manager(database_name)
        db_session = db_manager.get_session()
        por_count = db_session.query(db_manager.POR).count()
        db_session.close()
        
        return jsonify({
            'success': True, 
            'message': f'Switched to {company_info.display_name} database',
            'por_count': por_count,
            'database': database_name
        })
        
    except Exception as e:
        logger.error(f"Error switching database via API: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@routes.route('/test_database')
def test_database_api():
    """API endpoint to verify current database."""
    try:
        current_db = get_current_database()
        company_info = get_company_config(current_db)
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        por_count = db_session.query(db_manager.POR).count()
        db_session.close()
        
        return jsonify({
            'success': True,
            'current_database': current_db,
            'display_name': company_info.display_name,
            'por_count': por_count
        })
        
    except Exception as e:
        logger.error(f"Error testing database: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@routes.route('/get_database_info')
def get_database_info():
    """API endpoint to get current database information."""
    try:
        current_db = get_current_database()
        company_info = get_company_config(current_db)
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por_count = db_session.query(db_manager.POR).count()
        total_value = db_session.query(func.sum(db_manager.POR.order_total)).scalar() or 0
        
        db_session.close()
        
        return jsonify({
            'success': True,
            'current_database': current_db,
            'display_name': company_info.display_name,
            'total_pors': por_count,
            'total_value': float(total_value)
        })
        
    except Exception as e:
        logger.error(f"Error getting database info: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@routes.route('/')
def root():
    """Redirect root to dashboard."""
    return redirect(url_for('routes.dashboard'))


@routes.route('/upload', methods=['GET', 'POST'])
def upload():
    """Handle file upload and processing."""
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            logger.info(f"Upload request received. Files in request: {list(request.files.keys())}")
            
            if not file:
                logger.warning("No file found in request")
                flash("❌ No file selected", 'error')
                # Get current PO from database for template
                try:
                    current_db = get_current_database()
                    db_manager = get_database_manager(current_db)
                    db_session = db_manager.get_session()
                    counter = db_manager.get_or_create_batch_counter(db_session)
                    current_po_value = counter.value if counter else 1000
                    db_session.close()
                except Exception as e:
                    logger.error(f"Error getting current PO: {str(e)}")
                    current_po_value = 1000
                
                # Get current database info for template
                company_info = get_company_config(current_db)
                
                return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info, active_page='upload')
            
            logger.info(f"File object: {file}")
            logger.info(f"File filename: {file.filename}")
            logger.info(f"File content type: {getattr(file, 'content_type', 'unknown')}")
            logger.info(f"File content length: {getattr(file, 'content_length', 'unknown')}")
            logger.info(f"File headers: {dict(request.headers)}")
            
            # Check if file has content
            try:
                file.seek(0)
                first_bytes = file.read(100)
                file.seek(0)
                logger.info(f"First 100 bytes: {first_bytes}")
                logger.info(f"File size: {len(first_bytes)} bytes")
            except Exception as e:
                logger.error(f"Error reading file content: {str(e)}")
            
            # For main POR uploader, only allow Excel files
            if not allowed_excel_file(file.filename):
                logger.warning(f"File type not allowed for main uploader: {file.filename}")
                flash("❌ Only Excel files (.xlsx, .xls, .xlsm, .xltx, .xltm, .xlt, .xlm) are allowed for POR uploads", 'error')
                # Get current PO from database for template
                try:
                    current_db = get_current_database()
                    db_manager = get_database_manager(current_db)
                    db_session = db_manager.get_session()
                    counter = db_manager.get_or_create_batch_counter(db_session)
                    current_po_value = counter.value if counter else 1000
                    db_session.close()
                except Exception as e:
                    logger.error(f"Error getting current PO: {str(e)}")
                    current_po_value = 1000
                
                # Get current database info for template
                company_info = get_company_config(current_db)
                
                return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info, active_page='upload')
            
            success, message, data, line_items = process_uploaded_file(file)
            if success and data:
                # Display FDEC warning if applicable
                if data.get('fdec_warning'):
                    flash(data['fdec_warning'], 'warning')
                
                # Save to database
                save_success, save_message = save_por_to_database(data, line_items)
                if save_success:
                    # Check for batch completion after successful upload
                    try:
                        from flask import session
                        batch_end = session.get('batch_end', 0)
                        if batch_end > 0:
                            # Get current PO to check if we've reached the end
                            current_db = get_current_database()
                            db_manager = get_database_manager(current_db)
                            db_session = db_manager.get_session()
                            counter = db_manager.get_or_create_batch_counter(db_session)
                            current_po = counter.value if counter else 1000
                            db_session.close()
                            
                            if current_po > batch_end:
                                batch_message = f"⚠️ BATCH COMPLETE: Reached end of batch range. Please update with more batch numbers."
                                flash(f"{message} {batch_message}", 'success')
                            else:
                                flash(message, 'success')
                        else:
                            flash(message, 'success')
                    except Exception as e:
                        logger.error(f"Error checking batch completion: {str(e)}")
                        flash(message, 'success')
                    
                    # Redirect to view the newly created POR
                    try:
                        # Get the latest POR ID to redirect to
                        current_db = get_current_database()
                        db_manager = get_database_manager(current_db)
                        db_session = db_manager.get_session()
                        
                        latest_por = db_session.query(db_manager.POR).order_by(db_manager.POR.id.desc()).first()
                        db_session.close()
                        
                        if latest_por:
                            return redirect(url_for('routes.view', id=latest_por.id))
                        else:
                            return redirect(url_for('routes.view'))
                    except Exception as e:
                        logger.error(f"Error redirecting to view: {str(e)}")
                        return redirect(url_for('routes.view'))
                else:
                    flash(save_message, 'error')
            else:
                flash(message, 'error')
        except RequestEntityTooLarge:
            flash("❌ File too large. Maximum size is 16MB.", 'error')
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            flash(f"❌ Unexpected error: {str(e)}", 'error')
    
    # Get current PO from database for template
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po_value = counter.value if counter else 1000
        db_session.close()
    except Exception as e:
        logger.error(f"Error getting current PO: {str(e)}")
        current_po_value = 1000
    
    # Get current database info for template
    company_info = get_company_config(current_db)
    
    return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info, active_page='upload')


@routes.route('/check-updates')
def check_updates():
    """Check if there are new PORs or updates available."""
    try:
        import time
        from flask import jsonify
        
        # Use database-aware session
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        # Get the latest POR ID and count
        latest_por = db_session.query(db_manager.POR).order_by(db_manager.POR.id.desc()).first()
        total_count = db_session.query(db_manager.POR).count()
        
        # Get the last check time from request
        last_check = request.args.get('last_check', 0, type=float)
        
        has_new_data = False
        if latest_por:
            if hasattr(latest_por, 'created_at') and latest_por.created_at:
                por_created_timestamp = latest_por.created_at.timestamp()
                has_new_data = por_created_timestamp > last_check
            else:
                has_new_data = latest_por.id > int(last_check) if last_check > 0 else True
        
        db_session.close()
        
        return jsonify({
            'has_new_data': has_new_data,
            'latest_por_id': latest_por.id if latest_por else None,
            'total_count': total_count,
            'current_time': time.time()
        })
        
    except Exception as e:
        logger.error(f"Check updates error: {str(e)}")
        return jsonify({'has_new_data': False, 'error': str(e)})


@routes.route('/view')
def view():
    """Display single POR record with navigation."""
    import time
    try:
        por_id = request.args.get('id', type=int)
        logger.info(f"[DEBUG] View route - Received por_id: {por_id}")
        search_query = request.args.get('q', '').strip()
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()

        # If no specific ID provided, show list of all PORs (modern view)
        if not por_id:
            logger.info(f"[DEBUG] View route - Querying PORs from database: {current_db}")
            
            all_pors = db_session.query(db_manager.POR).order_by(db_manager.POR.id.desc()).all()
            logger.info(f"[DEBUG] View route - Found {len(all_pors)} PORs in database")
            
            # Log first few PORs for debugging
            for i, por in enumerate(all_pors[:3]):
                logger.info(f"[DEBUG] POR {i+1}: ID={por.id}, PO={por.po_number}, Company={por.company}, Project={por.ship_project_name}")
            
            # Prepare POR data for the list view
            por_data = []
            for por in all_pors:
                # Get line items count
                line_items_count = db_session.query(db_manager.LineItem).filter_by(por_id=por.id).count()
                
                # Get file count
                file_count = len(por.attached_files) if hasattr(por, 'attached_files') else 0
                
                por_data.append({
                    'id': por.id,
                    'po_number': por.po_number,
                    'project': por.ship_project_name or 'Unknown Project',
                    'requestor': por.requestor_name or 'Unknown',
                    'date': por.created_at.strftime('%d/%m/%Y') if por.created_at else 'Unknown',
                    'status': por.current_stage or 'received',
                    'company': por.company or current_db,
                    'line_items_count': line_items_count,
                    'file_count': file_count,
                    'order_total': float(por.order_total) if por.order_total else 0.0
                })
            
            logger.info(f"[DEBUG] View route - Prepared {len(por_data)} PORs for display")
            
            # Get current PO from database for template
            try:
                counter = db_manager.get_or_create_batch_counter(db_session)
                current_po_value = counter.value if counter else 1000
            except Exception as e:
                logger.error(f"Error getting current PO: {str(e)}")
                current_po_value = 1000
            
            db_session.close()
            
            # Get current database info for template
            company_info = get_company_config(current_db)
            logger.info(f"[DEBUG] View route - Company info: {company_info.display_name}")
            
            return render_template("modern_view.html", 
                                 all_pors=por_data,
                                 total_records=len(por_data),
                                 current_po=current_po_value,
                                 timestamp=int(time.time()),
                                 company=current_db,
                                 company_info=company_info,
                                 active_page='view')
        
        # Get the specific POR record
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        logger.info(f"[DEBUG] View route - Found por: {por}")
        if not por:
            flash("❌ PO record not found", 'error')
            return redirect(url_for('routes.view'))
        
        # Get navigation info
        total_records = db_session.query(db_manager.POR).count()
        
        # Get current position (1-based)
        current_position = db_session.query(db_manager.POR).filter(db_manager.POR.id <= por_id).count()
        
        # Get previous and next IDs
        prev_por = db_session.query(db_manager.POR).filter(db_manager.POR.id < por_id).order_by(db_manager.POR.id.desc()).first()
        next_por = db_session.query(db_manager.POR).filter(db_manager.POR.id > por_id).order_by(db_manager.POR.id.asc()).first()
        
        # Attach line items and file count
        por.line_items = db_session.query(db_manager.LineItem).filter_by(por_id=por.id).all()
        por.file_count = len(por.attached_files)
        por.files = por.attached_files
        
        # Add timestamp to force cache refresh and ensure latest data
        import time
        timestamp = int(time.time())
        
        # Get current PO from database for template
        try:
            counter = db_manager.get_or_create_batch_counter(db_session)
            current_po_value = counter.value if counter else 1000
        except Exception as e:
            logger.error(f"Error getting current PO: {str(e)}")
            current_po_value = 1000
        
        db_session.close()
        
        # Get current database info for template
        company_info = get_company_config(current_db)
        
        return render_template("modern_por_detail.html", 
                             por=por,
                             prev_id=prev_por.id if prev_por else None,
                             next_id=next_por.id if next_por else None,
                             current_po=current_po_value,
                             total_records=total_records,
                             current_position=current_position,
                             timestamp=timestamp,
                             company=current_db,
                             company_info=company_info)
                             
    except Exception as e:
        logger.error(f"View error: {str(e)}")
        flash(f"❌ Error loading record: {str(e)}", 'error')
        # Get current PO from database for template
        try:
            current_db = get_current_database()
            db_manager = get_database_manager(current_db)
            db_session = db_manager.get_session()
            counter = db_manager.get_or_create_batch_counter(db_session)
            current_po_value = counter.value if counter else 1000
            db_session.close()
        except Exception as e:
            logger.error(f"Error getting current PO: {str(e)}")
            current_po_value = 1000
        
        # Get current database info for template
        company_info = get_company_config(current_db)
        
        # For error case, always use modern_view.html since we're not showing a specific POR
        return render_template("modern_view.html", por=None, current_po=current_po_value, 
                             total_records=0, current_position=0, timestamp=int(time.time()), 
                             company=current_db, company_info=company_info)



@routes.route('/search')
def search():
    """Advanced search for PO records with intelligent matching and relevance scoring."""
    try:
        search_query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # all, date, po_number, requestor, supplier
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        stage_filter = request.args.get('stage', 'all')  # all, received, sent, filed
        content_type_filter = request.args.get('content_type', 'all')  # all, work_iwo, supply_and_fit, supply
        min_amount = request.args.get('min_amount', '')
        max_amount = request.args.get('max_amount', '')
        
        if not search_query and not date_from and not date_to and stage_filter == 'all' and content_type_filter == 'all' and not min_amount and not max_amount:
            return redirect(url_for('routes.view'))
        
        from datetime import datetime, timedelta
        from sqlalchemy import or_, and_, func, case, desc
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        # Start with base query
        query = db_session.query(db_manager.POR)
        
        # Apply filters
        filters = []
        
        # Date range filter
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
                filters.append(func.date(db_manager.POR.created_at) >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
                filters.append(func.date(db_manager.POR.created_at) <= to_date)
            except ValueError:
                pass
        
        # Stage filter
        if stage_filter != 'all':
            filters.append(db_manager.POR.current_stage == stage_filter)
        
        # Content type filter
        if content_type_filter != 'all':
            filters.append(db_manager.POR.content_type == content_type_filter)
        
        # Amount range filter
        if min_amount:
            try:
                min_val = float(min_amount)
                filters.append(db_manager.POR.order_total >= min_val)
            except ValueError:
                pass
        
        if max_amount:
            try:
                max_val = float(max_amount)
                filters.append(db_manager.POR.order_total <= max_val)
            except ValueError:
                pass
        
        # Text search with intelligent matching
        if search_query:
            # Check if it's a date search
            search_date = None
            try:
                # Try UK format first (DD/MM/YYYY)
                search_date = datetime.strptime(search_query, '%d/%m/%Y').date()
            except ValueError:
                try:
                    # Try US format (YYYY-MM-DD)
                    search_date = datetime.strptime(search_query, '%Y-%m-%d').date()
                except ValueError:
                    pass
            
            if search_date:
                # Date search
                filters.append(func.date(db_manager.POR.created_at) == search_date)
                search_type = 'date'
            else:
                # Text search with relevance scoring
                search_terms = search_query.split()
                search_conditions = []
                
                for term in search_terms:
                    term_pattern = f"%{term}%"
                    search_conditions.append(
                        or_(
                            db_manager.POR.po_number.like(term_pattern),
                            db_manager.POR.requestor_name.like(term_pattern),
                            db_manager.POR.ship_project_name.like(term_pattern),
                            db_manager.POR.supplier.like(term_pattern),
                            db_manager.POR.job_contract_no.like(term_pattern),
                            db_manager.POR.op_no.like(term_pattern),
                            db_manager.POR.description.like(term_pattern),
                            db_manager.POR.quote_ref.like(term_pattern),
                            db_manager.POR.specification_standards.like(term_pattern),
                            db_manager.POR.supplier_contact_name.like(term_pattern),
                            db_manager.POR.supplier_contact_email.like(term_pattern),
                            db_manager.POR.content_type.like(term_pattern)
                        )
                    )
                
                # Apply search conditions
                if search_conditions:
                    filters.append(or_(*search_conditions))
        
        # Apply all filters
        if filters:
            query = query.filter(and_(*filters))
        
        # Add relevance scoring for text searches
        if search_query and not search_date:
            # Create relevance score based on field importance and match quality
            relevance_score = case(
                (db_manager.POR.po_number.like(f"%{search_query}%"), 100),  # Exact PO number match
                (db_manager.POR.po_number.like(f"{search_query}%"), 90),    # PO number starts with
                (db_manager.POR.requestor_name.like(f"%{search_query}%"), 80),
                (db_manager.POR.ship_project_name.like(f"%{search_query}%"), 75),
                (db_manager.POR.supplier.like(f"%{search_query}%"), 70),
                (db_manager.POR.job_contract_no.like(f"%{search_query}%"), 65),
                (db_manager.POR.op_no.like(f"%{search_query}%"), 60),
                (db_manager.POR.description.like(f"%{search_query}%"), 50),
                (db_manager.POR.quote_ref.like(f"%{search_query}%"), 45),
                (db_manager.POR.specification_standards.like(f"%{search_query}%"), 40),
                (db_manager.POR.supplier_contact_name.like(f"%{search_query}%"), 35),
                (db_manager.POR.supplier_contact_email.like(f"%{search_query}%"), 30),
                (db_manager.POR.content_type.like(f"%{search_query}%"), 25),
                else_=0
            )
            
            # Add relevance score to query
            query = query.add_columns(relevance_score.label('relevance_score'))
            
            # Order by relevance score (descending) then by date (newest first)
            query = query.order_by(desc('relevance_score'), desc(db_manager.POR.id))
        else:
            # For date searches or filtered searches, order by date
            query = query.order_by(desc(db_manager.POR.id))
        
        # Execute query
        results = query.all()
        
        # Process results
        if search_query and not search_date:
            # Extract POR objects and relevance scores
            por_results = []
            for result in results:
                if hasattr(result, 'relevance_score'):
                    por = result[0]  # First element is the POR object
                    por.relevance_score = result[1]  # Second element is the relevance score
                else:
                    por = result
                    por.relevance_score = 0
                por_results.append(por)
        else:
            por_results = results
            # Ensure all POR objects have relevance_score attribute
            for por in por_results:
                if not hasattr(por, 'relevance_score'):
                    por.relevance_score = 0
        
        # Set file count and attachment icons for each POR record
        for por in por_results:
            por.file_count = len(por.attached_files)
            
            # Prepare attachment icons for display (max 4, one of each type)
            attachment_icons = []
            if por.attached_files:
                # Group files by type
                files_by_type = {}
                for file in por.attached_files:
                    if file.file_type not in files_by_type:
                        files_by_type[file.file_type] = []
                    files_by_type[file.file_type].append(file)
                
                # Add one icon for each file type (up to 4)
                for file_type, files in files_by_type.items():
                    if len(attachment_icons) < 4:
                        attachment_icons.append({
                            'type': file_type,
                            'count': len(files),
                            'icon': get_file_type_icon(file_type)
                        })
                
                # If we have more than 4 types, add a "+X" indicator
                if len(por.attached_files) > 4:
                    attachment_icons.append({
                        'type': 'more',
                        'count': len(por.attached_files) - 4,
                        'icon': '+'
                    })
            
            por.attachment_icons = attachment_icons
        
        # Generate search statistics
        total_results = len(por_results)
        if total_results > 0:
            # Calculate statistics
            total_value = sum(por.order_total or 0 for por in por_results)
            avg_value = total_value / total_results if total_results > 0 else 0
            stages_count = {}
            for por in por_results:
                stage = por.current_stage or 'received'
                stages_count[stage] = stages_count.get(stage, 0) + 1
            
            # No flash message needed - statistics are displayed in the search summary
            
            return render_template("search_results.html", 
                                 search_query=search_query,
                                 results=por_results,
                                 search_type=search_type,
                                 total_results=total_results,
                                 total_value=total_value,
                                 avg_value=avg_value,
                                 stages_count=stages_count,
                                 filters={
                                     'date_from': date_from,
                                     'date_to': date_to,
                                     'stage': stage_filter,
                                     'content_type': content_type_filter,
                                     'min_amount': min_amount,
                                     'max_amount': max_amount
                                 })
        else:
            # No results found
            if search_date:
                flash(f"❌ No POs found for date '{search_date.strftime('%d/%m/%Y')}'", 'error')
            else:
                flash(f"❌ No PO found matching '{search_query}'", 'error')
            return redirect(url_for('routes.view'))
        
        db_session.close()
            
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        flash(f"❌ Error searching: {str(e)}", 'error')
        return redirect(url_for('routes.view'))


@routes.route('/change-batch', methods=['GET', 'POST'])
def change_batch():
    """Handle batch number range updates for the currently active database."""
    if request.method == 'POST':
        try:
            # Check if this is a JSON request (from frontend)
            if request.is_json:
                data = request.get_json()
                batch_range = data.get('batch_range', '')
            else:
                batch_range = request.form.get('batch_range', '').strip()
            
            logger.info(f"[DEBUG] /change-batch POST hit. batch_range: {batch_range}")
            
            if not batch_range:
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Please enter a batch range'})
                else:
                    flash("❌ Please enter a batch range", 'error')
            else:
                # Parse batch range (e.g., "100-200")
                import re
                range_pattern = re.compile(r'^(\\d+)-(\\d+)$')
                match = range_pattern.match(batch_range)
                
                if not match:
                    if request.is_json:
                        return jsonify({'success': False, 'error': 'Invalid batch range format. Use: start-end (e.g., 100-200)'})
                    else:
                        flash("❌ Invalid batch range format. Use: start-end (e.g., 100-200)", 'error')
                else:
                    start_po = int(match.group(1))
                    end_po = int(match.group(2))
                    
                    if start_po >= end_po:
                        if request.is_json:
                            return jsonify({'success': False, 'error': 'Start number must be less than end number'})
                        else:
                            flash("❌ Start number must be less than end number", 'error')
                    else:
                        # Get the current database and update its batch counter
                        current_db = get_current_database()
                        logger.info(f"[DEBUG] Setting batch range for {current_db}: {start_po}-{end_po}")
                        
                        try:
                            # Use the new BatchNumberManager system
                            from batch_number_manager import get_batch_manager
                            
                            batch_manager = get_batch_manager(current_db)
                            logger.info(f"[DEBUG] Got batch manager for {current_db}")
                            
                            # Set the batch number to the start of the range
                            batch_manager.set_batch_number(start_po)
                            logger.info(f"[DEBUG] Batch number set to {start_po} using BatchNumberManager")
                            
                        except Exception as db_error:
                            logger.error(f"[DEBUG] BatchNumberManager error in change-batch: {str(db_error)}")
                            if request.is_json:
                                return jsonify({'success': False, 'error': f'Batch manager error: {str(db_error)}'})
                            else:
                                flash(f"❌ Batch manager error: {str(db_error)}", 'error')
                            company_info = get_company_config(current_db)
                            return render_template("change_batch.html", 
                                                 current_highest_po=0,
                                                 company=current_db,
                                                 company_info=company_info)
                        
                        # Store batch information in session for tracking
                        session['batch_start'] = start_po
                        session['batch_end'] = end_po
                        session['current_batch_po'] = start_po
                        
                        if request.is_json:
                            return jsonify({
                                'success': True, 
                                'message': f'Batch range {start_po}-{end_po} started successfully for {current_db.upper()}',
                                'current_po': start_po,
                                'batch_end': end_po,
                                'database': current_db
                            })
                        else:
                            flash(f"✅ Batch range {start_po}-{end_po} started successfully for {current_db.upper()}", 'success')
            
        except Exception as e:
            logger.error(f"Batch change error: {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details'}")
            if request.is_json:
                return jsonify({'success': False, 'error': f'Error updating batch: {str(e)}'})
            else:
                flash(f"❌ Error updating batch: {str(e)}", 'error')
    
    # Get current PO from database for template (for both GET and non-JSON POST)
    current_po_value = 0
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po_value = counter.value if counter else 1000 # Use the batch counter value
        db_session.close()
    except Exception as e:
        logger.error(f"Error getting current PO for change_batch template: {str(e)}")
        current_po_value = 1000 # Fallback
    
    # Get current database info for template
    company_info = get_company_config(current_db)
    
    return render_template("change_batch.html", 
                         current_po=current_po_value, # Pass current_po_value
                         company=current_db,
                         company_info=company_info,
                         active_page='change-batch')


@routes.route('/check-batch-status')
def check_batch_status():
    """Check current batch status and PO number for the currently active database."""
    try:
        # Get current PO from the active database
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po = counter.value if counter else 1000
        db_session.close()
        
        # Get batch information from session
        batch_start = session.get('batch_start', 0)
        batch_end = session.get('batch_end', 0)
        
        # Check if we've reached the end of the batch
        batch_complete = False
        if batch_end > 0 and current_po > batch_end:
            batch_complete = True
            # Reset batch info
            session.pop('batch_start', None)
            session.pop('batch_end', None)
            session.pop('current_batch_po', None)
        
        return jsonify({
            'current_po': current_po,
            'batch_start': batch_start,
            'batch_end': batch_end,
            'batch_complete': batch_complete,
            'database': current_db
        })
        
    except Exception as e:
        logger.error(f"Error checking batch status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@routes.route('/check-batch-completion')
def check_batch_completion():
    """Check if current PO has reached the end of the batch for the currently active database."""
    try:
        # Get current PO from the active database
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        counter = db_manager.get_or_create_batch_counter(db_session)
        current_po = counter.value if counter else 1000
        db_session.close()
        
        # Get batch information from session
        batch_start = session.get('batch_start', 0)
        batch_end = session.get('batch_end', 0)
        
        # Check if we've reached the end of the batch
        if batch_end > 0 and current_po > batch_end:
            return jsonify({
                'batch_complete': True,
                'message': f'Batch complete! Reached end of range ({batch_start}-{batch_end}). Please update with more batch numbers.',
                'current_po': current_po,
                'batch_end': batch_end,
                'database': current_db
            })
        else:
            return jsonify({
                'batch_complete': False,
                'current_po': current_po,
                'batch_end': batch_end,
                'database': current_db
            })
        
    except Exception as e:
        logger.error(f"Error checking batch completion: {str(e)}")
        return jsonify({'error': str(e)}), 500


@routes.route('/attach-files/<int:por_id>', methods=['GET', 'POST'])
def attach_files(por_id):
    """Handle file attachments for POR records."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()

        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            flash("❌ POR record not found", 'error')
            return redirect(url_for('routes.view'))
        
        # Get search context
        from_search = request.args.get('from_search', '')
        
        if request.method == 'POST':
            try:
                files = request.files.getlist('files')
                file_types = request.form.getlist('file_types')
                descriptions = request.form.getlist('descriptions')
                
                logger.info(f"Received {len(files)} files for upload")
                logger.info(f"File types: {file_types}")
                logger.info(f"Descriptions: {descriptions}")
                logger.info(f"All form data: {dict(request.form)}")
                logger.info(f"All files: {[f.filename for f in files if f]}")
                
                uploaded_count = 0
                for i, file in enumerate(files):
                    if file and file.filename:
                        logger.info(f"Processing file: {file.filename}")
                        logger.info(f"File extension: {file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'NO_EXTENSION'}")
                        logger.info(f"Allowed file check: {allowed_file(file.filename)}")
                        # Validate file
                        if not allowed_file(file.filename):
                            logger.warning(f"File {file.filename} not allowed")
                            continue
                        
                        # Get file info
                        file_type = file_types[i] if i < len(file_types) else 'other'
                        description = descriptions[i] if i < len(descriptions) else ''
                        
                        # Generate safe filename
                        original_filename = file.filename
                        file_extension = os.path.splitext(original_filename)[1]
                        safe_filename = f"POR_{por.po_number}_{file_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}{file_extension}"
                        
                        # Save file
                        company_config = get_company_config(current_db)
                        upload_folder = company_config.upload_folder
                        os.makedirs(upload_folder, exist_ok=True)
                        file_path = os.path.join(upload_folder, safe_filename)
                        file.save(file_path)
                        logger.info(f"File saved to: {file_path}")
                        file_size = os.path.getsize(file_path)
                        logger.info(f"File size: {file_size} bytes")
                        
                        # Create PORFile record
                        por_file = db_manager.PORFile(
                            por_id=por_id,
                            original_filename=original_filename,
                            stored_filename=safe_filename,
                            file_type=file_type,
                            file_size=file_size,
                            mime_type=file.content_type or 'application/octet-stream',
                            description=description
                        )
                        
                        db_session.add(por_file)
                        uploaded_count += 1
                        logger.info(f"Added file to database: {por_file.original_filename}")
                
                if uploaded_count > 0:
                    db_session.commit()
                    logger.info(f"Committed {uploaded_count} files to database")
                    message = f"✅ Successfully uploaded {uploaded_count} file(s)"
                    return jsonify({'success': True, 'message': message})
                else:
                    logger.warning("No files were uploaded")
                    return jsonify({'success': False, 'error': "No valid files were uploaded"})
                    
            except Exception as e:
                db_session.rollback()
                logger.error(f"File upload error: {str(e)}")
                return jsonify({'success': False, 'error': f"Error uploading files: {str(e)}"})
            finally:
                db_session.close()
        
        # For GET requests, render the template
        db_session = db_manager.get_session()
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        attached_files = por.attached_files if por else []
        
        # Prepare attachment icons for display (max 4, one of each type)
        attachment_icons = []
        if attached_files:
            # Group files by type
            files_by_type = {}
            for file in attached_files:
                if file.file_type not in files_by_type:
                    files_by_type[file.file_type] = []
                files_by_type[file.file_type].append(file)
            
            # Add one icon for each file type (up to 4)
            for file_type, files in files_by_type.items():
                if len(attachment_icons) < 4:
                    attachment_icons.append({
                        'type': file_type,
                        'count': len(files),
                        'icon': get_file_type_icon(file_type)
                    })
            
            # If we have more than 4 types, add a "+X" indicator
            if len(attached_files) > 4:
                attachment_icons.append({
                    'type': 'more',
                    'count': len(attached_files) - 4,
                    'icon': '+'
                })
        
        db_session.close()
        
        return render_template("modern_attach_files.html", por=por, attached_files=attached_files, attachment_icons=attachment_icons, from_search=from_search)
        
    except Exception as e:
        logger.error(f"Error in attach_files: {str(e)}")
        flash(f"❌ Error: {str(e)}", 'error')
        try:
            db_session.rollback()
            db_session.close()
        except:
            pass
        return redirect(url_for('routes.view'))


@routes.route('/view-file/<int:file_id>')
def view_file(file_id):
    """View an attached file in the browser."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        por_file = db_session.query(db_manager.PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('routes.view'))
        
        company_config = get_company_config(current_db)
        upload_folder = company_config.upload_folder
        file_path = os.path.join(upload_folder, por_file.stored_filename)
        
        if not os.path.exists(file_path):
            flash("❌ File not found on server", 'error')
            return redirect(url_for('routes.view'))
        
        db_session.close()
        
        # Determine MIME type based on file extension
        file_extension = por_file.original_filename.rsplit('.', 1)[1].lower() if '.' in por_file.original_filename else ''
        mime_type = 'application/octet-stream'  # default
        
        if file_extension in ['pdf']:
            mime_type = 'application/pdf'
        elif file_extension in ['jpg', 'jpeg']:
            mime_type = 'image/jpeg'
        elif file_extension in ['png']:
            mime_type = 'image/png'
        elif file_extension in ['xlsx', 'xls']:
            mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif file_extension in ['doc', 'docx']:
            mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif file_extension in ['eml']:
            mime_type = 'text/plain'  # .eml files as text
        elif file_extension in ['msg']:
            mime_type = 'application/vnd.ms-outlook'  # .msg files as Outlook format
        
        # Set headers to force inline viewing instead of download
        response = send_file(file_path, mimetype=mime_type, as_attachment=False)
        response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
        
        # Force inline viewing for all file types
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Type'] = mime_type
        
        return response
        
    except Exception as e:
        logger.error(f"View file error: {str(e)}")
        flash(f"❌ Error viewing file: {str(e)}", 'error')
        return redirect(url_for('routes.view'))


@routes.route('/open-file/<int:file_id>')
def open_file(file_id):
    """Open a file with proper handling for different file types."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        por_file = db_session.query(db_manager.PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('routes.view'))
        
        company_config = get_company_config(current_db)
        upload_folder = company_config.upload_folder
        file_path = os.path.join(upload_folder, por_file.stored_filename)
        
        if not os.path.exists(file_path):
            flash("❌ File not found on server", 'error')
            return redirect(url_for('routes.view'))
        
        db_session.close()
        
        # Determine file type and handle accordingly
        file_extension = por_file.original_filename.rsplit('.', 1)[1].lower() if '.' in por_file.original_filename else ''
        
        # For Excel files, serve as attachment (this is the most reliable way)
        if file_extension in ['xlsx', 'xls']:
            return send_file(
                file_path, 
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
        # For PDF files, serve inline
        elif file_extension in ['pdf']:
            response = send_file(file_path, mimetype='application/pdf', as_attachment=False)
            response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
            return response
        
        # For images, serve inline
        elif file_extension in ['jpg', 'jpeg', 'png']:
            mime_type = 'image/jpeg' if file_extension in ['jpg', 'jpeg'] else 'image/png'
            response = send_file(file_path, mimetype=mime_type, as_attachment=False)
            response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
            return response
        
        # For Word documents, serve as attachment to trigger "Open with" dialog
        elif file_extension in ['doc', 'docx']:
            if file_extension == 'docx':
                mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            else:
                mime_type = 'application/msword'
            return send_file(
                file_path, 
                mimetype=mime_type,
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
        # For email files, serve as text for .eml and attachment for .msg
        elif file_extension in ['eml', 'msg']:
            if file_extension == 'eml':
                # .eml files can be displayed as text in browser
                response = send_file(file_path, mimetype='text/plain', as_attachment=False)
                response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
                return response
            else:
                # .msg files need to be opened with Outlook or email client
                return send_file(
                    file_path, 
                    mimetype='application/vnd.ms-outlook',
                    as_attachment=True,
                    download_name=por_file.original_filename
                )
        
        # For other files, serve as attachment (this will trigger "Open with" dialog)
        else:
            return send_file(
                file_path, 
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Open file error: {str(e)}")
        flash(f"❌ Error opening file: {str(e)}", 'error')
        return redirect(url_for('routes.view'))


@routes.route('/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    """Delete an attached file."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        por_file = db_session.query(db_manager.PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('routes.view'))
        
        # Delete physical file
        company_config = get_company_config(current_db)
        upload_folder = company_config.upload_folder
        file_path = os.path.join(upload_folder, por_file.stored_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        db_session.delete(por_file)
        db_session.commit()
        db_session.close()
        
        flash("✅ File deleted successfully!", 'success')
        return redirect(url_for('routes.view', id=por_file.por_id))
        
    except Exception as e:
        logger.error(f"Delete file error: {str(e)}")
        flash(f"❌ Error deleting file: {str(e)}", 'error')
        return redirect(url_for('routes.view'))


@routes.route('/delete_por', methods=['POST'])
def delete_por():
    """Delete a POR record and its associated files and line items."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        po_number = data.get('po_number') # For logging/feedback
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        # Delete associated files
        for por_file in por.attached_files:
            company_config = get_company_config(current_db)
            upload_folder = company_config.upload_folder
            file_path = os.path.join(upload_folder, por_file.stored_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete POR and cascade delete line items and files via relationship
        db_session.delete(por)
        db_session.commit()
        db_session.close()
        
        logger.info(f"✅ Successfully deleted PO #{po_number} (ID: {por_id})")
        return jsonify({'success': True, 'message': f"PO #{po_number} deleted successfully"})
        
    except Exception as e:
        logger.error(f"Error deleting POR: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/update_timeline_stage', methods=['POST'])
def update_timeline_stage():
    """Update the timeline stage of a POR."""
    logger.info("update_timeline_stage endpoint hit")
    try:
        data = request.get_json()
        logger.info(f"Request data: {data}")
        por_id = data.get('por_id')
        stage = data.get('stage')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            logger.warning(f"POR with id {por_id} not found")
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        por.current_stage = stage
        por.stage_updated_at = datetime.now(timezone.utc) # Update timestamp
        
        db_session.commit()
        logger.info(f"Successfully updated stage for POR {por_id} to {stage}")
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Timeline stage updated'})
        
    except Exception as e:
        logger.error(f"Error updating timeline stage: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/add_timeline_comment', methods=['POST'])
def add_timeline_comment():
    """Add a comment to a specific timeline stage of a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        stage = data.get('stage')
        comment = data.get('comment')
        status_color = data.get('status_color', 'normal') # Get status color from frontend
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        new_comment_entry = f"[{timestamp}] {comment}"
        
        if stage == 'received':
            por.received_comments = new_comment_entry
        elif stage == 'sent':
            por.sent_comments = new_comment_entry
        elif stage == 'filed':
            por.filed_comments = new_comment_entry
        
        # Update status color if provided and different from current
        if status_color != 'normal': # Only update if it's a specific status (orange/red)
            por.status_color = status_color
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Comment added', 'status_color': por.status_color})
        
    except Exception as e:
        logger.error(f"Error adding timeline comment: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/delete_timeline_comment', methods=['POST'])
def delete_timeline_comment():
    """Delete a comment from a specific timeline stage of a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        stage = data.get('stage')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        if stage == 'received':
            por.received_comments = None
        elif stage == 'sent':
            por.sent_comments = None
        elif stage == 'filed':
            por.filed_comments = None
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Comment deleted'})
        
    except Exception as e:
        logger.error(f"Error deleting timeline comment: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/update_por_field', methods=['POST'])
def update_por_field():
    """Update a single field of a POR record."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        field = data.get('field')
        value = data.get('value')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        # Save old value for history
        old_value = getattr(por, field)
        
        # Type conversion for specific fields
        if field in ['order_total', 'price_each', 'quantity']:
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = 0.0 # Default to 0.0 if conversion fails
        
        setattr(por, field, value)
        
        # Add to change history
        add_change_to_history(por, field, old_value, value)
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': f'{field} updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating POR field {field}: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/update_line_item_field', methods=['POST'])
def update_line_item_field():
    """Update a single field of a LineItem record."""
    try:
        data = request.get_json()
        line_item_id = data.get('line_item_id')
        field = data.get('field')
        value = data.get('value')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        line_item = db_session.query(db_manager.LineItem).filter_by(id=line_item_id).first()
        
        if not line_item:
            db_session.close()
            return jsonify({'success': False, 'error': 'Line item not found'}), 404
        
        # Save old value for history (optional for line items)
        old_value = getattr(line_item, field)
        
        # Type conversion for specific fields
        if field in ['quantity', 'price_each', 'line_total']:
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = 0.0 # Default to 0.0 if conversion fails
        
        setattr(line_item, field, value)
        
        # Recalculate line_total if quantity or price_each changed
        if field in ['quantity', 'price_each']:
            line_item.line_total = (line_item.quantity or 0) * (line_item.price_each or 0)
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': f'{field} updated successfully', 'new_line_total': line_item.line_total})
        
    except Exception as e:
        logger.error(f"Error updating line item field {field}: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/add_line_item', methods=['POST'])
def add_line_item():
    """Add a new line item to a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        new_line_item = db_manager.LineItem(
            por_id=por_id,
            job_contract_no='',
            op_no='',
            description='',
            quantity=0,
            price_each=0.0,
            line_total=0.0
        )
        db_session.add(new_line_item)
        db_session.commit()
        
        # Get the ID of the newly created line item
        new_line_item_id = new_line_item.id
        
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Line item added successfully', 'line_item_id': new_line_item_id})
        
    except Exception as e:
        logger.error(f"Error adding line item: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/delete_line_item/<int:line_item_id>', methods=['DELETE'])
def delete_line_item(line_item_id):
    """Delete a line item from a POR."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        line_item = db_session.query(db_manager.LineItem).filter_by(id=line_item_id).first()
        
        if not line_item:
            db_session.close()
            return jsonify({'success': False, 'error': 'Line item not found'}), 404
        
        db_session.delete(line_item)
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Line item deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting line item: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/update_company', methods=['POST'])
def update_company():
    """Update the company for a POR record."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        company = data.get('company')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        por.company = company
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Company updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating company: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/undo_change', methods=['POST'])
def undo_change():
    """Undo the last change for a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        success, message = undo_last_change(por)
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        logger.error(f"Error undoing change: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/redo_change', methods=['POST'])
def redo_change():
    """Redo the last undone change for a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        success, message = redo_last_change(por)
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        logger.error(f"Error redoing change: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/update_content_type', methods=['POST'])
def update_content_type():
    """Update the content type of a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        content_type = data.get('content_type')
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        
        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()
        
        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404
        
        por.content_type = content_type
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'message': 'Content type updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating content type: {str(e)}")
        db_session.rollback()
        db_session.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@routes.route('/analytics')
def analytics():
    """Display analytics dashboard with POR statistics and charts."""
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()
        company_info = get_company_config(current_db)

        # Analytics data
        total_pors = db_session.query(db_manager.POR).count()
        total_value = db_session.query(func.sum(db_manager.POR.order_total)).scalar() or 0
        active_pors = db_session.query(db_manager.POR).filter(db_manager.POR.current_stage != 'filed').count()
        completed_pors = db_session.query(db_manager.POR).filter(db_manager.POR.current_stage == 'filed').count()

        # Status distribution
        status_dist = db_session.query(db_manager.POR.current_stage, func.count(db_manager.POR.id)).group_by(db_manager.POR.current_stage).all()
        status_labels = [row[0] for row in status_dist]
        status_data = [row[1] for row in status_dist]

        # Content type distribution
        content_type_dist = db_session.query(db_manager.POR.content_type, func.count(db_manager.POR.id)).group_by(db_manager.POR.content_type).all()
        content_type_labels = [row[0] for row in content_type_dist]
        content_type_data = [row[1] for row in content_type_dist]

        # Top suppliers
        top_suppliers = db_session.query(db_manager.POR.supplier, func.sum(db_manager.POR.order_total).label('total_value')).group_by(db_manager.POR.supplier).order_by(func.sum(db_manager.POR.order_total).desc()).limit(5).all()

        # Top requestors
        top_requestors = db_session.query(db_manager.POR.requestor_name, func.count(db_manager.POR.id).label('por_count')).group_by(db_manager.POR.requestor_name).order_by(func.count(db_manager.POR.id).desc()).limit(5).all()

        # Monthly data
        monthly_data = db_session.query(func.strftime('%Y-%m', db_manager.POR.created_at), func.count(db_manager.POR.id), func.sum(db_manager.POR.order_total)).group_by(func.strftime('%Y-%m', db_manager.POR.created_at)).order_by(func.strftime('%Y-%m', db_manager.POR.created_at)).all()
        monthly_labels = [row[0] for row in monthly_data]
        monthly_counts = [row[1] for row in monthly_data]
        monthly_values = [float(row[2]) if row[2] is not None else 0.0 for row in monthly_data]

        db_session.close()

        analytics_data = {
            'company': current_db,
            'company_info': company_info,
            'total_pors': total_pors,
            'total_value': total_value,
            'active_pors': active_pors,
            'completed_pors': completed_pors,
            'status_labels': status_labels,
            'status_data': status_data,
            'content_type_labels': content_type_labels,
            'content_type_data': content_type_data,
            'top_suppliers': top_suppliers,
            'top_requestors': top_requestors,
            'monthly_labels': monthly_labels,
            'monthly_counts': monthly_counts,
            'monthly_values': monthly_values,
            'active_page': 'analytics'
        }

        return render_template('analytics.html', **analytics_data)
        
    except Exception as e:
        logger.error(f"Error loading analytics: {str(e)}")
        flash(f'Error loading analytics: {str(e)}', 'error')
        return redirect(url_for('routes.dashboard'))


@routes.route('/update_order_type', methods=['POST'])
def update_order_type_route():
    """Update the order type of a POR."""
    try:
        data = request.get_json()
        por_id = data.get('por_id')
        order_type = data.get('order_type')

        if not por_id or not order_type:
            return jsonify({'success': False, 'error': 'Missing POR ID or order type'}), 400

        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        db_session = db_manager.get_session()

        por = db_session.query(db_manager.POR).filter_by(id=por_id).first()

        if not por:
            db_session.close()
            return jsonify({'success': False, 'error': 'POR not found'}), 404

        # Update the order_type
        por.order_type = order_type
        db_session.commit()
        db_session.close()

        return jsonify({'success': True, 'message': 'Order type updated successfully'})

    except Exception as e:
        logger.error(f"Error updating order type: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@routes.route('/settings')
def settings():
    """Display the settings page."""
    try:
        current_db = get_current_database()
        company_info = get_company_config(current_db)
        
        return render_template('settings.html', 
                             company=current_db, 
                             company_info=company_info, 
                             active_page='settings')
    except Exception as e:
        logger.error(f"Error loading settings page: {str(e)}")
        flash(f'Error loading settings page: {str(e)}', 'error')
        return redirect(url_for('routes.dashboard'))


@routes.route('/logs')
def logs():
    """Display the application logs."""
    try:
        with open('logs.txt', 'r', encoding='utf-8') as f:
            logs = f.read()
    except FileNotFoundError:
        logs = "No logs found."
    
    current_db = get_current_database()
    company_info = get_company_config(current_db)
    
    return render_template('logs.html', logs=logs, company=current_db, company_info=company_info, active_page='logs')
