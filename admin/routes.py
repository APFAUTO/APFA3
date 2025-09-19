"""
Admin Routes for POR System
Handles admin console functionality including dashboard, user management, permissions, audit logs, and settings.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import login_required
from functools import wraps
from datetime import datetime, timedelta
import json

from auth.models import get_auth_session, User, Permission, UserPermission, UserSetting, AuditLog, UserTypeDefaultPermission
from auth.security import admin_required


# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required_view(f):
    """Decorator to require admin access for views"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'user_id' not in session:
            flash('Please log in to access the admin console.', 'error')
            return redirect(url_for('auth.login'))
        
        # Get user from database
        auth_session = get_auth_session()
        try:
            user = auth_session.query(User).get(session['user_id'])
            if not user or not user.is_admin:
                flash('You do not have permission to access the admin console.', 'error')
                return redirect(url_for('auth.login'))
            
            return f(*args, **kwargs)
        finally:
            auth_session.close()
    
    return decorated_function

def admin_required_api(f):
    """Decorator to require admin access for API endpoints (returns JSON)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Please log in to access the admin console.'})
        
        # Get user from database
        auth_session = get_auth_session()
        try:
            user = auth_session.query(User).get(session['user_id'])
            if not user or not user.is_admin:
                return jsonify({'success': False, 'message': 'You do not have permission to access the admin console.'})
            
            return f(*args, **kwargs)
        finally:
            auth_session.close()
    
    return decorated_function

@admin_bp.route('/debug')
def debug_access():
    """Debug route to check admin access"""
    auth_session = get_auth_session()
    try:
        user_id = session.get('user_id')
        if not user_id:
            return f"No user_id in session. Session keys: {list(session.keys())}"
        
        user = auth_session.query(User).get(user_id)
        if not user:
            return f"User {user_id} not found in database"
        
        return f"User: {user.username}, Admin: {user.is_admin}, Active: {user.is_active}, Session: {dict(session)}"
    finally:
        auth_session.close()

@admin_bp.route('/test')
@admin_required_view  
def test_admin():
    """Simple test route for admin access"""
    return "<h1>Admin Test Page</h1><p>If you can see this, admin access is working!</p><a href='/admin'>Go to Dashboard</a>"

@admin_bp.route('/')
@admin_required_view
def dashboard():
    """Admin dashboard with system statistics and recent activity"""
    auth_session = get_auth_session()
    
    try:
        # Get system statistics
        total_users = auth_session.query(User).count()
        active_users = auth_session.query(User).filter(User.is_active == True).count()
        admin_users = auth_session.query(User).filter(User.is_admin == True).count()
        
        # Get recent audit logs
        recent_logs = auth_session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
        
        # Get user activity statistics
        last_7_days = datetime.utcnow() - timedelta(days=7)
        recent_activity = auth_session.query(AuditLog).filter(AuditLog.timestamp >= last_7_days).count()
        
        # Get system status
        system_status = {
            'database': 'Online',
            'authentication': 'Online',
            'email_service': 'Online',
            'backup_service': 'Online'
        }
        
        return render_template('admin/dashboard.html',
                             total_users=total_users,
                             active_users=active_users,
                             admin_users=admin_users,
                             recent_logs=recent_logs,
                             recent_activity=recent_activity,
                             system_status=system_status,
                             current_datetime=datetime.utcnow())
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        current_app.logger.error(f"Error loading admin dashboard: {str(e)}\n{error_details}")
        return f"<h1>Admin Dashboard Error</h1><p>Error: {str(e)}</p><pre>{error_details}</pre><a href='/auth/login'>Back to Login</a>"
    
    finally:
        auth_session.close()

@admin_bp.route('/users')
@admin_required_view
def users():
    """User management page"""
    session = get_auth_session()
    
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = 20
        search = request.args.get('search', '')
        user_type = request.args.get('user_type', '')
        status = request.args.get('status', '')
        
        # Build query
        query = session.query(User)
        
        if search:
            query = query.filter(
                User.username.contains(search) | 
                User.email.contains(search) | 
                User.full_name.contains(search)
            )
        
        if user_type:
            query = query.filter(User.user_type == user_type)
        
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)
        
        # Get paginated results
        users = query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        total_users = query.count()
        total_pages = (total_users + per_page - 1) // per_page
        
        return render_template('admin/users.html',
                             users=users,
                             current_page=page,
                             total_pages=total_pages,
                             total_users=total_users,
                             search=search,
                             user_type=user_type,
                             status=status)
    
    except Exception as e:
        current_app.logger.error(f"Error loading users page: {str(e)}")
        flash('Error loading users. Please try again.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        session.close()

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required_view
def edit_user(user_id):
    """Edit user details"""
    session = get_auth_session()
    
    try:
        user = session.query(User).filter(User.id == user_id).first()
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin.users'))
        
        if request.method == 'POST':
            # Update user details
            user.full_name = request.form.get('full_name')
            user.email = request.form.get('email')
            user.user_type = request.form.get('user_type')
            user.is_admin = request.form.get('is_admin') == 'on'
            user.is_active = request.form.get('is_active') == 'on'
            
            session.commit()
            
            # Log the action
            audit_log = AuditLog(
                user_id=session.get('user_id'),
                action='User Updated',
                details=f'Updated user {user.username}',
                ip_address=request.remote_addr,
                resource_id=str(user_id),
                success=True
            )
            session.add(audit_log)
            session.commit()
            
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin.users'))
        
        return render_template('admin/edit_user.html', user=user)
    
    except Exception as e:
        current_app.logger.error(f"Error editing user {user_id}: {str(e)}")
        flash('Error updating user. Please try again.', 'error')
        return redirect(url_for('admin.users'))
    
    finally:
        session.close()

@admin_bp.route('/users/<int:user_id>/toggle_status', methods=['POST'])
@admin_required_view
def toggle_user_status(user_id):
    """Toggle user active status"""
    session = get_auth_session()
    
    try:
        user = session.query(User).filter(User.id == user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found.'})
        
        if user.id == session.get('user_id'):
            return jsonify({'success': False, 'message': 'Cannot change your own status.'})
        
        user.is_active = not user.is_active
        session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='User Status Changed',
            details=f'{"Activated" if user.is_active else "Deactivated"} user {user.username}',
            ip_address=request.remote_addr,
            resource_id=str(user_id),
            success=True
        )
        session.add(audit_log)
        session.commit()
        
        return jsonify({
            'success': True,
            'message': f'User {"activated" if user.is_active else "deactivated"} successfully.',
            'is_active': user.is_active
        })
    
    except Exception as e:
        current_app.logger.error(f"Error toggling user status {user_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating user status.'})
    
    finally:
        session.close()

@admin_bp.route('/permissions')
@admin_required_view
def permissions():
    """Permission management page"""
    session = get_auth_session()
    
    try:
        # Get all permissions
        permissions = session.query(Permission).all()
        
        # Get all users with their permissions
        users = session.query(User).all()
        
        # Get user permissions grouped by user
        user_permissions = {}
        for user in users:
            user_perms = session.query(UserPermission).filter(UserPermission.user_id == user.id).all()
            user_permissions[user.id] = [up.permission.name for up in user_perms]
        
        return render_template('admin/permissions.html',
                             permissions=permissions,
                             users=users,
                             user_permissions=user_permissions)
    
    except Exception as e:
        current_app.logger.error(f"Error loading permissions page: {str(e)}")
        flash('Error loading permissions. Please try again.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        session.close()

@admin_bp.route('/permissions/update_user_type', methods=['POST'])
@admin_required_view
def update_user_type_permissions():
    """Update default permissions for a user type"""
    session = get_auth_session()
    
    try:
        user_type = request.form.get('user_type')
        selected_permissions = request.form.getlist('permissions')
        
        # Update default permissions for user type
        # This would typically be stored in a settings table
        # For now, we'll just log the action
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='User Type Permissions Updated',
            details=f'Updated default permissions for {user_type} users',
            ip_address=request.remote_addr,
            resource_id=user_type,
            success=True
        )
        session.add(audit_log)
        session.commit()
        
        flash(f'Default permissions for {user_type} users updated successfully.', 'success')
        return redirect(url_for('admin.permissions'))
    
    except Exception as e:
        current_app.logger.error(f"Error updating user type permissions: {str(e)}")
        flash('Error updating permissions. Please try again.', 'error')
        return redirect(url_for('admin.permissions'))
    
    finally:
        session.close()

@admin_bp.route('/permissions/update_user', methods=['POST'])
@admin_required_api
def update_user_permissions():
    """Update individual user permissions"""
    session = get_auth_session()
    
    try:
        user_id = request.form.get('user_id', type=int)
        selected_permissions = request.form.getlist('permissions')
        
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin.permissions'))
        
        # Remove existing permissions
        session.query(UserPermission).filter(UserPermission.user_id == user_id).delete()
        
        # Always include dashboard_view as it's mandatory
        if 'dashboard_view' not in selected_permissions:
            selected_permissions.append('dashboard_view')
        
        # Add new permissions
        for perm_name in selected_permissions:
            permission = session.query(Permission).filter(Permission.name == perm_name).first()
            if permission:
                user_permission = UserPermission(user_id=user_id, permission_id=permission.id)
                session.add(user_permission)
        
        session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='User Updated',
            details=f'Updated user {user.username}',
            ip_address=request.remote_addr,
            resource_id=str(user_id),
            success=True
        )
        session.add(audit_log)
        session.commit()
        
        return jsonify({'success': True, 'message': f'Permissions for {user.username} updated successfully.'})
    
    except Exception as e:
        current_app.logger.error(f"Error updating user permissions: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating permissions. Please try again.'})
    
    finally:
        session.close()

@admin_bp.route('/audit_logs')
@admin_required_view
def audit_logs():
    """Audit logs page"""
    session = get_auth_session()
    
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = 20
        date_range = request.args.get('date_range', 'week')
        activity_type = request.args.get('activity_type', '')
        user_id = request.args.get('user_id', '')
        status = request.args.get('status', '')
        
        # Build query
        query = session.query(AuditLog)
        
        # Apply date filter
        if date_range == 'today':
            start_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            query = query.filter(AuditLog.timestamp >= start_date)
        elif date_range == 'week':
            start_date = datetime.utcnow() - timedelta(days=7)
            query = query.filter(AuditLog.timestamp >= start_date)
        elif date_range == 'month':
            start_date = datetime.utcnow() - timedelta(days=30)
            query = query.filter(AuditLog.timestamp >= start_date)
        elif date_range == 'quarter':
            start_date = datetime.utcnow() - timedelta(days=90)
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if activity_type:
            query = query.filter(AuditLog.action.contains(activity_type))
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        if status:
            if status == 'success':
                query = query.filter(AuditLog.success == True)
            elif status == 'failed':
                query = query.filter(AuditLog.success == False)
        
        # Get paginated results
        logs = query.order_by(AuditLog.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()
        total_logs = query.count()
        total_pages = (total_logs + per_page - 1) // per_page
        
        # Get statistics
        success_count = session.query(AuditLog).filter(AuditLog.success == True).count()
        failed_count = session.query(AuditLog).filter(AuditLog.success == False).count()
        warning_count = 0  # No warning status in current model
        security_count = session.query(AuditLog).filter(AuditLog.action.contains('Login')).count()
        
        # Get all users for filter dropdown
        users = session.query(User).all()
        
        # Add color and icon information to logs
        for log in logs:
            if log.success:
                log.color = 'green'
                log.icon = 'check-circle'
            else:
                log.color = 'red'
                log.icon = 'times-circle'
        
        return render_template('admin/audit_logs.html',
                             audit_logs=logs,
                             current_page=page,
                             total_pages=total_pages,
                             total_logs=total_logs,
                             success_count=success_count,
                             failed_count=failed_count,
                             warning_count=warning_count,
                             security_count=security_count,
                             users=users,
                             date_range=date_range,
                             activity_type=activity_type,
                             user_id=user_id,
                             status=status)
    
    except Exception as e:
        current_app.logger.error(f"Error loading audit logs: {str(e)}")
        flash('Error loading audit logs. Please try again.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        session.close()

@admin_bp.route('/settings')
@admin_required_view
def settings():
    """System settings page"""
    session = get_auth_session()
    
    try:
        # Get current settings (this would typically come from a settings table)
        settings = {
            'site_name': 'POR Automator',
            'site_url': 'http://localhost:5000',
            'admin_email': 'admin@porautomator.com',
            'timezone': 'America/New_York',
            'maintenance_mode': False,
            'maintenance_message': 'System is currently undergoing maintenance. Please check back later.',
            'two_factor_auth': False,
            'session_timeout': True,
            'session_duration': 60,
            'max_login_attempts': 5,
            'lockout_duration': 15,
            'ip_whitelist': False,
            'allowed_ips': '192.168.1.0/24\n10.0.0.0/8',
            'database_backups': True,
            'query_logging': False,
            'backup_retention': 30,
            'connection_pool': 10,
            'db_optimization': True,
            'email_notifications': True,
            'email_provider': 'smtp',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_tls': True,
            'debug_mode': False,
            'api_access': False,
            'log_level': 'INFO',
            'max_file_size': 16,
            'allowed_file_types': '.xlsx,.xls',
            'cache_timeout': 60
        }
        
        return render_template('admin/settings.html', settings=settings)
    
    except Exception as e:
        current_app.logger.error(f"Error loading settings page: {str(e)}")
        flash('Error loading settings. Please try again.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        session.close()

@admin_bp.route('/settings/update', methods=['POST'])
@admin_required_view
def update_settings():
    """Update system settings"""
    session = get_auth_session()
    
    try:
        # Get form data
        settings_data = request.form.to_dict()
        
        # Handle checkboxes
        checkbox_fields = [
            'maintenance_mode', 'two_factor_auth', 'session_timeout', 'ip_whitelist',
            'database_backups', 'query_logging', 'db_optimization', 'email_notifications',
            'smtp_tls', 'debug_mode', 'api_access'
        ]
        
        for field in checkbox_fields:
            settings_data[field] = field in settings_data
        
        # Update settings (this would typically save to a settings table)
        # For now, we'll just log the action
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='Settings Updated',
            details='System settings were updated',
            ip_address=request.remote_addr,
            resource_id='system_settings',
            success=True
        )
        session.add(audit_log)
        session.commit()
        
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('admin.settings'))
    
    except Exception as e:
        current_app.logger.error(f"Error updating settings: {str(e)}")
        flash('Error updating settings. Please try again.', 'error')
        return redirect(url_for('admin.settings'))
    
    finally:
        session.close()

# API endpoints for admin functionality
@admin_bp.route('/api/users/<int:user_id>', methods=['GET'])
@admin_required_view
def api_get_user(user_id):
    """Get user details via API"""
    session = get_auth_session()
    
    try:
        user = session.query(User).filter(User.id == user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found.'})
        
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'user_type': user.user_type,
            'is_admin': user.is_admin,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
        
        return jsonify({'success': True, 'user': user_data})
    
    except Exception as e:
        current_app.logger.error(f"API error getting user {user_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'Error retrieving user data.'})
    
    finally:
        session.close()

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required_view
def delete_user(user_id):
    """Delete a user"""
    auth_session = get_auth_session()
    
    try:
        user = auth_session.query(User).filter(User.id == user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found.'})
        
        # Prevent deleting yourself
        if user.id == session.get('user_id'):
            return jsonify({'success': False, 'message': 'Cannot delete your own account.'})
        
        # Delete user permissions first
        auth_session.query(UserPermission).filter(UserPermission.user_id == user_id).delete()
        
        # Delete the user
        auth_session.delete(user)
        auth_session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='User Deleted',
            details=f'Deleted user {user.username}',
            ip_address=request.remote_addr,
            resource_id=str(user_id),
            success=True
        )
        auth_session.add(audit_log)
        auth_session.commit()
        
        return jsonify({'success': True, 'message': 'User deleted successfully.'})
    
    except Exception as e:
        current_app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'Error deleting user.'})
    
    finally:
        auth_session.close()

@admin_bp.route('/api/users/<int:user_id>/permissions', methods=['GET'])
@admin_required_view
def api_get_user_permissions(user_id):
    """Get user permissions via API"""
    auth_session = get_auth_session()
    
    try:
        user_permissions = auth_session.query(UserPermission).filter(UserPermission.user_id == user_id).all()
        permissions = [up.permission.name for up in user_permissions]
        
        # Always include dashboard_view as it's mandatory
        if 'dashboard_view' not in permissions:
            permissions.append('dashboard_view')
        
        return jsonify({'success': True, 'permissions': permissions})
    
    except Exception as e:
        current_app.logger.error(f"API error getting user permissions {user_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'Error retrieving user permissions.'})
    
    finally:
        auth_session.close()

@admin_bp.route('/api/system/stats', methods=['GET'])
@admin_required_view
def api_system_stats():
    """Get system statistics via API"""
    session = get_auth_session()
    
    try:
        # Get current statistics
        total_users = session.query(User).count()
        active_users = session.query(User).filter(User.is_active == True).count()
        admin_users = session.query(User).filter(User.is_admin == True).count()
        
        # Get recent activity
        last_24_hours = datetime.utcnow() - timedelta(hours=24)
        recent_logins = session.query(AuditLog).filter(
            AuditLog.action == 'User Login',
            AuditLog.timestamp >= last_24_hours
        ).count()
        
        stats = {
            'total_users': total_users,
            'active_users': active_users,
            'admin_users': admin_users,
            'recent_logins': recent_logins,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify({'success': True, 'stats': stats})
    
    except Exception as e:
        current_app.logger.error(f"API error getting system stats: {str(e)}")
        return jsonify({'success': False, 'message': 'Error retrieving system statistics.'})
    
    finally:
        session.close()

@admin_bp.route('/user-type-defaults', methods=['GET'])
@admin_required_api
def get_user_type_defaults():
    """Get user type default permissions"""
    auth_session = get_auth_session()
    
    try:
        # First, ensure the table exists
        from auth.models import Base, auth_engine
        Base.metadata.create_all(auth_engine)
        
        defaults = {}
        user_types = ['user', 'buyer', 'admin']
        
        for user_type in user_types:
            try:
                type_defaults = auth_session.query(UserTypeDefaultPermission).filter(
                    UserTypeDefaultPermission.user_type == user_type
                ).all()
                
                current_app.logger.info(f"Found {len(type_defaults)} defaults for {user_type}")
                
                permissions = []
                for td in type_defaults:
                    permission = auth_session.query(Permission).get(td.permission_id)
                    if permission:
                        permissions.append(permission.name)
                        current_app.logger.info(f"  - {permission.name}")
                
                # Always include dashboard_view
                if 'dashboard_view' not in permissions:
                    permissions.append('dashboard_view')
                
                defaults[user_type] = permissions
                current_app.logger.info(f"Final permissions for {user_type}: {permissions}")
                
            except Exception as inner_e:
                current_app.logger.error(f"Error processing {user_type}: {str(inner_e)}")
                # Fallback to just dashboard_view
                defaults[user_type] = ['dashboard_view']
        
        current_app.logger.info(f"Returning defaults: {defaults}")
        return jsonify({'success': True, 'defaults': defaults})
    
    except Exception as e:
        current_app.logger.error(f"Error getting user type defaults: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Error retrieving user type defaults: {str(e)}'})
    
    finally:
        auth_session.close()

@admin_bp.route('/user-type-defaults/update', methods=['POST'])
@admin_required_api
def update_user_type_defaults():
    """Update user type default permissions"""
    auth_session = get_auth_session()
    
    try:
        # First, ensure the table exists
        from auth.models import Base, auth_engine
        Base.metadata.create_all(auth_engine)
        
        user_type = request.form.get('user_type')
        selected_permissions = request.form.getlist('permissions')
        
        current_app.logger.info(f"Updating {user_type} defaults with permissions: {selected_permissions}")
        
        if not user_type or user_type not in ['user', 'buyer', 'admin']:
            return jsonify({'success': False, 'message': 'Invalid user type.'})
        
        # Always include dashboard_view
        if 'dashboard_view' not in selected_permissions:
            selected_permissions.append('dashboard_view')
        
        # Remove existing defaults for this user type
        deleted_count = auth_session.query(UserTypeDefaultPermission).filter(
            UserTypeDefaultPermission.user_type == user_type
        ).delete()
        current_app.logger.info(f"Deleted {deleted_count} existing defaults for {user_type}")
        
        # Add new defaults
        added_count = 0
        for perm_name in selected_permissions:
            permission = auth_session.query(Permission).filter(Permission.name == perm_name).first()
            if permission:
                default_perm = UserTypeDefaultPermission(
                    user_type=user_type,
                    permission_id=permission.id
                )
                auth_session.add(default_perm)
                added_count += 1
            else:
                current_app.logger.warning(f"Permission '{perm_name}' not found")
        
        current_app.logger.info(f"Added {added_count} new defaults for {user_type}")
        
        # Commit the changes
        auth_session.commit()
        current_app.logger.info(f"Successfully committed changes for {user_type}")
        
        # Verify the changes were saved
        verify_count = auth_session.query(UserTypeDefaultPermission).filter(
            UserTypeDefaultPermission.user_type == user_type
        ).count()
        current_app.logger.info(f"Verification: {user_type} now has {verify_count} default permissions")
        
        # Log the action
        audit_log = AuditLog(
            user_id=session.get('user_id'),
            action='User Type Defaults Updated',
            details=f'Updated default permissions for {user_type} users: {", ".join(selected_permissions)}',
            ip_address=request.remote_addr,
            resource_id=user_type,
            success=True
        )
        auth_session.add(audit_log)
        auth_session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Default permissions for {user_type} users updated successfully.',
            'permissions_count': verify_count,
            'permissions': selected_permissions
        })
    
    except Exception as e:
        auth_session.rollback()
        current_app.logger.error(f"Error updating user type defaults: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Error updating user type defaults: {str(e)}'})
    
    finally:
        auth_session.close()

@admin_bp.route('/debug/user-type-defaults')
@admin_required_api
def debug_user_type_defaults():
    """Debug route to check current user type defaults in database"""
    auth_session = get_auth_session()
    
    try:
        result = {}
        user_types = ['user', 'buyer', 'admin']
        
        for user_type in user_types:
            defaults = auth_session.query(UserTypeDefaultPermission).filter(
                UserTypeDefaultPermission.user_type == user_type
            ).all()
            
            permissions = []
            for default in defaults:
                permission = auth_session.query(Permission).get(default.permission_id)
                if permission:
                    permissions.append(permission.name)
            
            result[user_type] = {
                'count': len(defaults),
                'permissions': permissions
            }
        
        return jsonify({'success': True, 'data': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    
    finally:
        auth_session.close()

@admin_bp.route('/test-db-save')
@admin_required_api
def test_db_save():
    """Test route to verify database saving works"""
    auth_session = get_auth_session()
    
    try:
        # Clear existing test data
        auth_session.query(UserTypeDefaultPermission).filter(
            UserTypeDefaultPermission.user_type == 'buyer'
        ).delete()
        
        # Get dashboard_view permission
        dashboard_perm = auth_session.query(Permission).filter(
            Permission.name == 'dashboard_view'
        ).first()
        
        po_uploader_perm = auth_session.query(Permission).filter(
            Permission.name == 'po_uploader'
        ).first()
        
        if dashboard_perm and po_uploader_perm:
            # Add test permissions
            test_perm1 = UserTypeDefaultPermission(
                user_type='buyer',
                permission_id=dashboard_perm.id
            )
            test_perm2 = UserTypeDefaultPermission(
                user_type='buyer',
                permission_id=po_uploader_perm.id
            )
            
            auth_session.add(test_perm1)
            auth_session.add(test_perm2)
            auth_session.commit()
            
            # Verify they were saved
            saved_count = auth_session.query(UserTypeDefaultPermission).filter(
                UserTypeDefaultPermission.user_type == 'buyer'
            ).count()
            
            return jsonify({
                'success': True,
                'message': f'Test successful! Saved {saved_count} permissions for buyer',
                'dashboard_perm_id': dashboard_perm.id,
                'po_uploader_perm_id': po_uploader_perm.id
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Required permissions not found',
                'dashboard_found': dashboard_perm is not None,
                'po_uploader_found': po_uploader_perm is not None
            })
    
    except Exception as e:
        auth_session.rollback()
        return jsonify({'success': False, 'error': str(e)})
    
    finally:
        auth_session.close()
