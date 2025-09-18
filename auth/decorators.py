"""
Authentication and permission decorators.
Provides reusable decorators for route protection and permission checking.
"""

from functools import wraps
from flask import session, flash, redirect, url_for, request

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        
        from auth.database import get_auth_session
        from auth.models import User
        
        auth_session = get_auth_session()
        user = auth_session.query(User).get(session['user_id'])
        
        if not user or not user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('main.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            from auth.database import get_auth_session
            from auth.permissions import PermissionManager
            
            auth_session = get_auth_session()
            permission_manager = PermissionManager(auth_session)
            
            if not permission_manager.check_permission(session['user_id'], permission_name):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('main.dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def company_access_required(f):
    """Decorator to require company selection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'company' not in session:
            flash('Please select a company to continue.', 'error')
            return redirect(url_for('company.select'))
        return f(*args, **kwargs)
    return decorated_function

def active_user_required(f):
    """Decorator to require active user account"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        
        from auth.database import get_auth_session
        from auth.models import User
        
        auth_session = get_auth_session()
        user = auth_session.query(User).get(session['user_id'])
        
        if not user or not user.is_active:
            flash('Account is disabled.', 'error')
            return redirect(url_for('auth.login'))
        
        return f(*args, **kwargs)
    return decorated_function

def no_cache(f):
    """Decorator to prevent browser caching"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Add cache control headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    return decorated_function

def json_response_required(f):
    """Decorator to require JSON response format"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if client accepts JSON
        if 'application/json' not in request.accept_mimetypes:
            return jsonify({'error': 'JSON response required'}), 406
        
        return f(*args, **kwargs)
    return decorated_function

# Combined decorators for common use cases
def authenticated_admin_required(f):
    """Combined decorator: login + admin required"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return admin_required(login_required(f))(*args, **kwargs)
    return decorated_function

def authenticated_permission_required(permission_name):
    """Combined decorator: login + permission required"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return permission_required(permission_name)(login_required(f))(*args, **kwargs)
        return decorated_function
    return decorator

def authenticated_company_access_required(f):
    """Combined decorator: login + company access required"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return company_access_required(login_required(f))(*args, **kwargs)
    return decorated_function

# Template context processors
def inject_user():
    """Inject user information into template context"""
    if 'user_id' not in session:
        return {}
    
    return {
        'current_user': {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'full_name': session.get('full_name'),
            'user_type': session.get('user_type'),
            'is_admin': session.get('is_admin', False)
        }
    }

def inject_permissions():
    """Inject user permissions into template context"""
    if 'user_id' not in session:
        return {'has_permission': lambda perm: False}
    
    from auth.database import get_auth_session
    from auth.permissions import PermissionManager
    
    auth_session = get_auth_session()
    permission_manager = PermissionManager(auth_session)
    
    def permission_checker(permission_name):
        return permission_manager.check_permission(session['user_id'], permission_name)
    
    return {'has_permission': permission_checker}

# Error handlers
def handle_auth_error(error):
    """Handle authentication errors"""
    flash('Authentication required.', 'error')
    return redirect(url_for('auth.login'))

def handle_permission_error(error):
    """Handle permission errors"""
    flash('Insufficient permissions.', 'error')
    return redirect(url_for('main.dashboard'))

def handle_company_error(error):
    """Handle company selection errors"""
    flash('Company selection required.', 'error')
    return redirect(url_for('company.select'))
