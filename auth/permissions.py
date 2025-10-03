"""
Permission management system.
Handles permission checking, granting, and user access control.
"""

from functools import wraps
from flask import session, flash, redirect, url_for
from extensions import db
from auth.models import User, Permission, UserPermission, UserTypeDefaultPermission

# Permission decorator
def permission_required(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            user_id = session['user_id']
            
            user = db.session.query(User).get(user_id)
            if not user or not user.is_active:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            # Admin users have all permissions
            if user.is_admin:
                return f(*args, **kwargs)
            
            # Dashboard and System Settings permissions are mandatory for all active users
            if permission_name in ['dashboard_view', 'system_settings']:
                return f(*args, **kwargs)
            
            # Special handling for file_validation: if user has po_uploader, they also have file_validation
            if permission_name == 'file_validation':
                po_uploader_permission = db.session.query(Permission).filter(
                    Permission.name == 'po_uploader',
                    Permission.is_active == True
                ).first()
                if po_uploader_permission:
                    user_has_po_uploader = db.session.query(UserPermission).filter(
                        UserPermission.user_id == user_id,
                        UserPermission.permission_id == po_uploader_permission.id,
                        UserPermission.is_active == True
                    ).first()
                    if user_has_po_uploader:
                        return f(*args, **kwargs)

            # Check specific permission
            permission = db.session.query(Permission).filter(
                Permission.name == permission_name,
                Permission.is_active == True
            ).first()
            
            if not permission:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            # Check user permission
            user_permission = db.session.query(UserPermission).filter(
                UserPermission.user_id == user_id,
                UserPermission.permission_id == permission.id,
                UserPermission.is_active == True
            ).first()
            
            if user_permission is None:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper function for template usage
def has_permission(permission_name):
    """Check if current user has permission (for template use)"""
    if 'user_id' not in session:
        return False
    
    user_id = session['user_id']
    
    user = db.session.query(User).get(user_id)
    if not user or not user.is_active:
        return False
    
    # Admin users have all permissions
    if user.is_admin:
        return True
    
    # Dashboard and System Settings permissions are mandatory for all active users
    if permission_name in ['dashboard_view', 'system_settings']:
        return True
    
    # Special handling for file_validation: if user has po_uploader, they also have file_validation
    if permission_name == 'file_validation':
        po_uploader_permission = db.session.query(Permission).filter(
            Permission.name == 'po_uploader',
            Permission.is_active == True
        ).first()
        if po_uploader_permission:
            user_has_po_uploader = db.session.query(UserPermission).filter(
                UserPermission.user_id == user_id,
                UserPermission.permission_id == po_uploader_permission.id,
                UserPermission.is_active == True
            ).first()
            if user_has_po_uploader:
                return True
    
    # Check specific permission
    permission = db.session.query(Permission).filter(
        Permission.name == permission_name,
        Permission.is_active == True
    ).first()
    
    if not permission:
        return False
    
    # Check user permission
    user_permission = db.session.query(UserPermission).filter(
        UserPermission.user_id == user_id,
        UserPermission.permission_id == permission.id,
        UserPermission.is_active == True
    ).first()
    
    return user_permission is not None

# Helper function to get user permissions for template
def get_user_permissions_for_template():
    """Get user permissions for template rendering"""
    if 'user_id' not in session:
        return {}
    
    user_id = session['user_id']
    
    user = db.session.query(User).get(user_id)
    if not user or not user.is_active:
        return {}
    
    # Admin users have all permissions
    if user.is_admin:
        # Return all active permissions for admin
        permissions = db.session.query(Permission).filter(Permission.is_active == True).all()
        categorized_permissions = {
            'upload': [], 'view': [], 'diagnostic': [], 'admin': []
        }
        for perm in permissions:
            if perm.category in categorized_permissions:
                categorized_permissions[perm.category].append({
                    'name': perm.name,
                    'description': perm.description
                })
        return categorized_permissions

    permissions = db.session.query(
        Permission.name, Permission.description, Permission.category
    ).join(UserPermission).filter(
        UserPermission.user_id == user_id,
        UserPermission.is_active == True,
        Permission.is_active == True
    ).all()
    
    # Group by category
    categorized_permissions = {
        'Core': [], # Added new category
        'upload': [],
        'view': [],
        'diagnostic': [],
        'admin': []
    }
    
    for perm in permissions:
        if perm.category in categorized_permissions:
            categorized_permissions[perm.category].append({
                'name': perm.name,
                'description': perm.description
            })
    
    return categorized_permissions

def grant_permission(user_id, permission_name, granted_by_user_id):
    """Grant permission to user"""
    permission = db.session.query(Permission).filter(
        Permission.name == permission_name
    ).first()
    
    if not permission:
        return False, "Permission not found"
    
    # Check if permission already exists
    existing = db.session.query(UserPermission).filter(
        UserPermission.user_id == user_id,
        UserPermission.permission_id == permission.id
    ).first()
    
    if existing:
        existing.is_active = True
        existing.granted_by = granted_by_user_id
    else:
        new_permission = UserPermission(
            user_id=user_id,
            permission_id=permission.id,
            granted_by=granted_by_user_id
        )
        db.session.add(new_permission)
    
    db.session.commit()
    return True, "Permission granted successfully"

def revoke_permission(user_id, permission_name):
    """Revoke permission from user"""
    # Dashboard permission is mandatory and cannot be revoked
    if permission_name == 'dashboard_view':
        return False, "Dashboard permission is mandatory and cannot be revoked"
    
    permission = db.session.query(Permission).filter(
        Permission.name == permission_name
    ).first()
    
    if not permission:
        return False, "Permission not found"
    
    user_permission = db.session.query(UserPermission).filter(
        UserPermission.user_id == user_id,
        UserPermission.permission_id == permission.id
    ).first()
    
    if user_permission:
        user_permission.is_active = False
        db.session.commit()
        return True, "Permission revoked successfully"
    
    return False, "User does not have this permission"

def get_all_permissions():
    """Get all available permissions"""
    permissions = db.session.query(Permission).filter(
        Permission.is_active == True
    ).all()
    
    # Group by category
    categorized_permissions = {
        'Core': [], # Added new category
        'upload': [],
        'view': [],
        'diagnostic': [],
        'admin': [],
        'Management': []
    }
    
    for perm in permissions:
        if perm.category in categorized_permissions:
            categorized_permissions[perm.category].append({
                'id': perm.id,
                'name': perm.name,
                'description': perm.description
            })
    
    return categorized_permissions

def get_users_with_permission(permission_name):
    """Get all users who have a specific permission"""
    permission = db.session.query(Permission).filter(
        Permission.name == permission_name
    ).first()
    
    if not permission:
        return []
    
    users = db.session.query(User).join(UserPermission).filter(
        UserPermission.permission_id == permission.id,
        UserPermission.is_active == True,
        User.is_active == True
    ).all()
    
    return users

def grant_user_type_permissions(user_id, user_type):
    """Grant default permissions based on user type from database configuration"""
    if user_type not in ['admin', 'buyer', 'user']:
        return False, f"Unknown user type: {user_type}"
    
    try:
        # Try to get default permissions for this user type from database
        type_defaults = []
        try:
            type_defaults = db.session.query(UserTypeDefaultPermission).filter(
                UserTypeDefaultPermission.user_type == user_type
            ).all()
            print(f"🔍 Found {len(type_defaults)} database defaults for {user_type}")
        except Exception as db_error:
            print(f"⚠️ Database table error: {str(db_error)}")
            print(f"💡 Using fallback defaults for {user_type}")
        
        # If no defaults found or table doesn't exist, use fallback defaults
        if not type_defaults:
            print(f"⚠️ No database defaults found for {user_type}, using fallback")
            fallback_permissions = {
                'admin': ['dashboard_view', 'por_search', 'por_detail', 'po_uploader', 'batch_management', 'analytics_view', 'system_logs', 'database_access', 'user_management', 'system_settings', 'ppe_logger_view', 'por_detail_view'],
                'buyer': ['dashboard_view', 'system_settings', 'po_uploader', 'batch_management', 'analytics_view', 'ppe_logger_view', 'por_detail_view'],
                'user': ['dashboard_view', 'system_settings', 'por_detail_view']
            }
            
            permissions_to_grant = db.session.query(Permission).filter(
                Permission.name.in_(fallback_permissions[user_type]),
                Permission.is_active == True
            ).all()
            print(f"📝 Using fallback permissions: {[p.name for p in permissions_to_grant]}")
        else:
            # Use configured defaults
            permission_ids = [td.permission_id for td in type_defaults]
            permissions_to_grant = db.session.query(Permission).filter(
                Permission.id.in_(permission_ids),
                Permission.is_active == True
            ).all()
            print(f"✅ Using database defaults: {[p.name for p in permissions_to_grant]}")
        
        # Always ensure dashboard_view is included
        dashboard_permission = db.session.query(Permission).filter(
            Permission.name == 'dashboard_view',
            Permission.is_active == True
        ).first()
        
        if dashboard_permission and dashboard_permission not in permissions_to_grant:
            permissions_to_grant.append(dashboard_permission)
        
        # Grant permissions
        granted_count = 0
        print(f"🎯 Granting {len(permissions_to_grant)} permissions to user {user_id}")
        for permission in permissions_to_grant:
            existing = db.session.query(UserPermission).filter(
                UserPermission.user_id == user_id,
                UserPermission.permission_id == permission.id
            ).first()
            
            if not existing:
                new_permission = UserPermission(
                    user_id=user_id,
                    permission_id=permission.id,
                    granted_by=user_id  # Self-granted based on user type
                )
                db.session.add(new_permission)
                granted_count += 1
                print(f"  ✅ Granted: {permission.name}")
            else:
                existing.is_active = True
                print(f"  🔄 Reactivated: {permission.name}")
        
        db.session.commit()
        print(f"💾 Committed {granted_count} new permissions for user {user_id}")
        return True, f"Default {user_type} permissions granted ({granted_count} permissions)"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error granting permissions: {str(e)}"
