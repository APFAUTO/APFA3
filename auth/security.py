"""
Security utilities for authentication system.
Handles password hashing, validation, and security operations.
"""

import re
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import session, flash, redirect, url_for, request

class SecurityManager:
    """Handles security operations and authentication"""
    
    def __init__(self, auth_session):
        self.auth_session = auth_session
    
    def hash_password(self, password):
        """Hash password using bcrypt"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        return bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(password_hash, str):
            password_hash = password_hash.encode('utf-8')
        return bcrypt.checkpw(password, password_hash)
    
    def is_password_strong(self, password):
        """Check password strength requirements"""
        errors = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        if errors:
            return False, " | ".join(errors)
        
        return True, "Password meets requirements"
    
    def handle_login_attempt(self, user, success, ip_address=None, user_agent=None):
        """Handle login attempt logging and lockout"""
        if success:
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
        else:
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        
        # Log attempt
        from auth.models import AuditLog
        audit_log = AuditLog(
            user_id=user.id if success else None,
            action='login_attempt',
            resource_type='authentication',
            ip_address=ip_address or request.remote_addr,
            user_agent=user_agent or request.headers.get('User-Agent', ''),
            success=success,
            details=f"Login attempt {'successful' if success else 'failed'} for user: {user.username}"
        )
        
        self.auth_session.add(audit_log)
        self.auth_session.commit()
    
    def is_account_locked(self, user):
        """Check if user account is locked"""
        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining_time = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            return True, f"Account locked. Try again after {remaining_time} minutes"
        return False, ""
    
    def log_security_event(self, user_id, action, resource_type=None, resource_id=None, 
                          success=True, details=None):
        """Log security event to audit trail"""
        from auth.models import AuditLog
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            success=success,
            details=details
        )
        
        self.auth_session.add(audit_log)
        self.auth_session.commit()
    
    def validate_password_reset_token(self, token):
        """Validate password reset token (placeholder for future implementation)"""
        # This would typically involve JWT or similar token validation
        # For now, return False as placeholder
        return False

class InputValidator:
    """Validates and sanitizes user input"""
    
    @staticmethod
    def sanitize_username(username):
        """Sanitize username input"""
        # Remove special characters except alphanumeric and underscore
        sanitized = re.sub(r'[^\w]', '', username)
        return sanitized.lower()
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def sanitize_search_query(query):
        """Sanitize search queries to prevent SQL injection"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[;\'"\\]', '', query)
        return sanitized.strip()
    
    @staticmethod
    def validate_file_type(filename, allowed_extensions):
        """Validate file type"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in allowed_extensions
    
    @staticmethod
    def sanitize_string(input_string, max_length=255):
        """Sanitize string input"""
        if not input_string:
            return ""
        
        # Remove HTML tags and special characters
        sanitized = re.sub(r'<[^>]*>', '', input_string)
        sanitized = re.sub(r'[\'"\\]', '', sanitized)
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()

# Authentication decorators
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
            return redirect(url_for('auth.login'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

def is_safe_url(target):
    """Check if URL is safe for redirect"""
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Add is_safe_url method to SecurityManager class
SecurityManager.is_safe_url = staticmethod(is_safe_url)
