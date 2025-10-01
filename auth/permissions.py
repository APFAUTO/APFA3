"""
Permission management system.
Handles permission checking, granting, and user access control.
"""

from functools import wraps
from flask import session, flash, redirect, url_for

class PermissionManager:
    """Centralized permission management system"""
    
    def __init__(self, auth_session):
        self.auth_session = auth_session
    
    def check_permission(self, user_id, permission_name):
        """Check if user has specific permission"""
        from auth.models import User, Permission, UserPermission
        
        user = self.auth_session.query(User).get(user_id)
        if not user or not user.is_active:
            return False
        
        # Admin users have all permissions
        if user.is_admin:
            return True
        
        # Dashboard and System Settings permissions are mandatory for all active users
        if permission_name in ['dashboard_view', 'system_settings']:
            return True
        
        # Check specific permission
        permission = self.auth_session.query(Permission).filter(
            Permission.name == permission_name,
            Permission.is_active == True
        ).first()
        
        if not permission:
            return False
        
        # Check user permission
        user_permission = self.auth_session.query(UserPermission).filter(
            UserPermission.user_id == user_id,
            UserPermission.permission_id == permission.id,
            UserPermission.is_active == True
        ).first()
        
        return user_permission is not None
    
    def get_user_permissions(self, user_id):
        """Get all permissions for a user"""
        from auth.models import Permission, UserPermission
        
        permissions = self.auth_session.query(
            Permission.name, Permission.description, Permission.category
        ).join(UserPermission).filter(
            UserPermission.user_id == user_id,
            UserPermission.is_active == True,
            Permission.is_active == True
        ).all()
        
        # Group by category
        categorized_permissions = {
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
    
    def grant_permission(self, user_id, permission_name, granted_by_user_id):
        """Grant permission to user"""
        from auth.models import Permission, UserPermission
        
        permission = self.auth_session.query(Permission).filter(
            Permission.name == permission_name
        ).first()
        
        if not permission:
            return False, "Permission not found"
        
        # Check if permission already exists
        existing = self.auth_session.query(UserPermission).filter(
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
            self.auth_session.add(new_permission)
        
        self.auth_session.commit()
        return True, "Permission granted successfully"
    
    def revoke_permission(self, user_id, permission_name):
        """Revoke permission from user"""
        from auth.models import Permission, UserPermission
        
        # Dashboard permission is mandatory and cannot be revoked
        if permission_name == 'dashboard_view':
            return False, "Dashboard permission is mandatory and cannot be revoked"
        
        permission = self.auth_session.query(Permission).filter(
            Permission.name == permission_name
        ).first()
        
        if not permission:
            return False, "Permission not found"
        
        user_permission = self.auth_session.query(UserPermission).filter(
            UserPermission.user_id == user_id,
            UserPermission.permission_id == permission.id
        ).first()
        
        if user_permission:
            user_permission.is_active = False
            self.auth_session.commit()
            return True, "Permission revoked successfully"
        
        return False, "User does not have this permission"
    
    def get_all_permissions(self):
        """Get all available permissions"""
        from auth.models import Permission
        
        permissions = self.auth_session.query(Permission).filter(
            Permission.is_active == True
        ).all()
        
        # Group by category
        categorized_permissions = {
            'upload': [],
            'view': [],
            'diagnostic': [],
            'admin': []
        }
        
        for perm in permissions:
            if perm.category in categorized_permissions:
                categorized_permissions[perm.category].append({
                    'id': perm.id,
                    'name': perm.name,
                    'description': perm.description
                })
        
        return categorized_permissions
    
    def get_users_with_permission(self, permission_name):
        """Get all users who have a specific permission"""
        from auth.models import User, Permission, UserPermission
        
        permission = self.auth_session.query(Permission).filter(
            Permission.name == permission_name
        ).first()
        
        if not permission:
            return []
        
        users = self.auth_session.query(User).join(UserPermission).filter(
            UserPermission.permission_id == permission.id,
            UserPermission.is_active == True,
            User.is_active == True
        ).all()
        
        return users
    
    def grant_user_type_permissions(self, user_id, user_type):
        """Grant default permissions based on user type from database configuration"""
        from auth.models import Permission, UserPermission, UserTypeDefaultPermission
        
        if user_type not in ['admin', 'buyer', 'user']:
            return False, f"Unknown user type: {user_type}"
        
        try:
            # Try to get default permissions for this user type from database
            type_defaults = []
            try:
                type_defaults = self.auth_session.query(UserTypeDefaultPermission).filter(
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
                    'admin': ['dashboard_view', 'por_search', 'por_detail', 'po_uploader', 'batch_management', 'file_validation', 'analytics_view', 'system_logs', 'database_access', 'user_management', 'system_settings'],
                    'buyer': ['dashboard_view', 'system_settings', 'por_search', 'por_detail', 'po_uploader', 'batch_management', 'file_validation', 'analytics_view'],
                    'user': ['dashboard_view', 'system_settings', 'por_search', 'por_detail']
                }
                
                permissions_to_grant = self.auth_session.query(Permission).filter(
                    Permission.name.in_(fallback_permissions[user_type]),
                    Permission.is_active == True
                ).all()
                print(f"📝 Using fallback permissions: {[p.name for p in permissions_to_grant]}")
            else:
                # Use configured defaults
                permission_ids = [td.permission_id for td in type_defaults]
                permissions_to_grant = self.auth_session.query(Permission).filter(
                    Permission.id.in_(permission_ids),
                    Permission.is_active == True
                ).all()
                print(f"✅ Using database defaults: {[p.name for p in permissions_to_grant]}")
            
            # Always ensure dashboard_view is included
            dashboard_permission = self.auth_session.query(Permission).filter(
                Permission.name == 'dashboard_view',
                Permission.is_active == True
            ).first()
            
            if dashboard_permission and dashboard_permission not in permissions_to_grant:
                permissions_to_grant.append(dashboard_permission)
            
            # Grant permissions
            granted_count = 0
            print(f"🎯 Granting {len(permissions_to_grant)} permissions to user {user_id}")
            for permission in permissions_to_grant:
                existing = self.auth_session.query(UserPermission).filter(
                    UserPermission.user_id == user_id,
                    UserPermission.permission_id == permission.id
                ).first()
                
                if not existing:
                    new_permission = UserPermission(
                        user_id=user_id,
                        permission_id=permission.id,
                        granted_by=user_id  # Self-granted based on user type
                    )
                    self.auth_session.add(new_permission)
                    granted_count += 1
                    print(f"  ✅ Granted: {permission.name}")
                else:
                    existing.is_active = True
                    print(f"  🔄 Reactivated: {permission.name}")
            
            self.auth_session.commit()
            print(f"💾 Committed {granted_count} new permissions for user {user_id}")
            return True, f"Default {user_type} permissions granted ({granted_count} permissions)"
            
        except Exception as e:
            self.auth_session.rollback()
            return False, f"Error granting permissions: {str(e)}"
    
    def check_multiple_permissions(self, user_id, permission_names):
        """Check if user has all specified permissions"""
        results = {}
        for permission_name in permission_names:
            results[permission_name] = self.check_permission(user_id, permission_name)
        return results
    
    def get_permission_matrix(self):
        """Get permission matrix for admin view"""
        from auth.models import User, Permission, UserPermission
        
        # Get all active users and permissions
        users = self.auth_session.query(User).filter(User.is_active == True).all()
        permissions = self.auth_session.query(Permission).filter(Permission.is_active == True).all()
        
        # Build matrix
        matrix = []
        for user in users:
            user_permissions = set()
            user_perms = self.auth_session.query(UserPermission).filter(
                UserPermission.user_id == user.id,
                UserPermission.is_active == True
            ).all()
            
            for up in user_perms:
                user_permissions.add(up.permission_id)
            
            row = {
                'user_id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'user_type': user.user_type,
                'is_admin': user.is_admin,
                'permissions': {}
            }
            
            for permission in permissions:
                # Ensure dashboard appears as granted for all users in the matrix
                if permission.name == 'dashboard_view':
                    row['permissions'][permission.name] = True
                else:
                    row['permissions'][permission.name] = permission.id in user_permissions
            
            matrix.append(row)
        
        return matrix

# Permission decorator
def permission_required(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('auth.login'))
            
            from auth.database import get_auth_session
            
            auth_session = get_auth_session()
            permission_manager = PermissionManager(auth_session)
            
            if not permission_manager.check_permission(session['user_id'], permission_name):
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
    
    from auth.database import get_auth_session
    
    auth_session = get_auth_session()
    permission_manager = PermissionManager(auth_session)
    
    return permission_manager.check_permission(session['user_id'], permission_name)

# Helper function to get user permissions for template
def get_user_permissions_for_template():
    """Get user permissions for template rendering"""
    if 'user_id' not in session:
        return {}
    
    from auth.database import get_auth_session
    
    auth_session = get_auth_session()
    permission_manager = PermissionManager(auth_session)
    
    return permission_manager.get_user_permissions(session['user_id'])
