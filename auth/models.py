"""
Authentication models for user management and permissions.
Defines the database schema for users, permissions, and audit logs.
"""

import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from app import db # Import db from app.py

class User(db.Model, UserMixin):
    """User model for authentication"""
    __tablename__ = "users"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Basic information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    
    # User type and permissions
    user_type = db.Column(db.String(20), nullable=False)  # 'admin', 'buyer', 'user'
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Security
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    force_password_change = db.Column(db.Boolean, default=False)
    
    # Relationships
    permissions = db.relationship("UserPermission", back_populates="user", foreign_keys="[UserPermission.user_id]")
    settings = db.relationship("UserSetting", back_populates="user")
    audit_logs = db.relationship("AuditLog", back_populates="user")
    granted_permissions = db.relationship("UserPermission", back_populates="granted_by_user", foreign_keys="[UserPermission.granted_by]")
    
    def __repr__(self):
        return f"<User {self.username}>"
    
    @property
    def full_name(self):
        """Get user's full name"""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_locked(self):
        """Check if user account is locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def get_lockout_time_remaining(self):
        """Get remaining lockout time in minutes"""
        if not self.locked_until or self.locked_until <= datetime.utcnow():
            return 0
        return int((self.locked_until - datetime.utcnow()).total_seconds() / 60)

class Permission(db.Model):
    """Permission model for feature access control"""
    __tablename__ = "permissions"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Permission details
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    category = db.Column(db.String(30), nullable=False)  # 'upload', 'view', 'admin', 'diagnostic'
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user_permissions = db.relationship("UserPermission", back_populates="permission")
    
    def __repr__(self):
        return f"<Permission {self.name}>"

class UserPermission(db.Model):
    """Many-to-many relationship between users and permissions"""
    __tablename__ = "user_permissions"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)
    
    # Metadata
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship("User", back_populates="permissions", foreign_keys=[user_id])
    permission = db.relationship("Permission", back_populates="user_permissions")
    granted_by_user = db.relationship("User", back_populates="granted_permissions", foreign_keys=[granted_by])
    
    def __repr__(self):
        return f"<UserPermission {self.user_id}:{self.permission_id}>"

class UserSetting(db.Model):
    """User-specific settings and preferences"""
    __tablename__ = "user_settings"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Setting details
    setting_key = db.Column(db.String(50), nullable=False)
    setting_value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship("User", back_populates="settings")
    
    def __repr__(self):
        return f"<UserSetting {self.user_id}:{self.setting_key}>"

class UserTypeDefaultPermission(db.Model):
    """Default permissions for user types"""
    __tablename__ = "user_type_default_permissions"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # User type and permission
    user_type = db.Column(db.String(20), nullable=False)  # 'admin', 'buyer', 'user'
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    permission = db.relationship("Permission")
    
    def __repr__(self):
        return f"<UserTypeDefaultPermission {self.user_type}:{self.permission_id}>"

class AuditLog(db.Model):
    """Audit log for tracking user actions and system events"""
    __tablename__ = "audit_logs"
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # User information
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Action details
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    
    # Request information
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamp and status
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text)
    
    # Relationships
    user = db.relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog {self.action} by {self.user_id}>"

# Create indexes for performance
db.Index('idx_users_username', User.username)
db.Index('idx_users_email', User.email)
db.Index('idx_permissions_name', Permission.name)
db.Index('idx_audit_logs_timestamp', AuditLog.timestamp)
db.Index('idx_audit_logs_user_id', AuditLog.user_id)

def get_auth_session():
    """Get a new authentication database session"""
    return db.session

def create_auth_tables(db_instance):
    """Create all authentication tables"""
    db_instance.create_all()
    print("Authentication database tables created successfully")

def init_default_permissions(db_instance):
    """Initialize default permissions in the database"""
    session = db_instance.session
    
    try:
        # Check if permissions already exist
        existing_count = session.query(Permission).count()
        if existing_count > 0:
            print(f"Permissions already exist ({existing_count} found)")
            return
        
        # Default permissions
        default_permissions = [
            # Core Permissions
            ('dashboard_view', 'View main dashboard', 'Core'),
            ('system_settings', 'Modify system settings (includes audit logs, database management, company switching)', 'Core'),
            ('diagnostic_views', 'Access diagnostic views', 'Core'),

            # Management Permissions
            ('po_uploader', 'Upload Purchase Order files and view POR details', 'Management'),
            ('batch_management', 'Manage batch numbers', 'Management'),
            ('file_validation', 'Validate uploaded files', 'Management'),
            ('user_management', 'Manage users', 'Management'),

            # System Permissions

            # Admin Permissions
            ('admin_access', 'Access the admin console', 'Admin'),
            ('permission_management', 'Manage user permissions', 'Admin'),
            ('user_creation', 'Create new user accounts', 'Admin'),
            ('system_monitoring', 'Monitor system health and performance', 'Admin')
        ]
        
        # Create permissions
        for name, description, category in default_permissions:
            permission = Permission(
                name=name,
                description=description,
                category=category
            )
            session.add(permission)
        
        session.commit()
        print(f"Created {len(default_permissions)} default permissions")
        
    except Exception as e:
        session.rollback()
        print(f"Error creating default permissions: {e}")
    finally:
        session.close()

def create_default_admin_user(db_instance):
    """Create default admin user if none exists"""
    session = db_instance.session
    
    try:
        # Check if admin user already exists
        admin_user = session.query(User).filter(User.username == 'admin').first()
        if admin_user:
            print("Admin user already exists")
            return
        
        # Import bcrypt here to avoid circular imports
        import bcrypt
        
        # Create admin user
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=password_hash,
            first_name='System',
            last_name='Administrator',
            user_type='admin',
            is_admin=True,
            is_active=True
        )
        
        session.add(admin_user)
        session.flush()  # Get the user ID
        
        # Grant all permissions to admin user
        all_permissions = session.query(Permission).all()
        for permission in all_permissions:
            user_permission = UserPermission(
                user_id=admin_user.id,
                permission_id=permission.id,
                granted_by=admin_user.id
            )
            session.add(user_permission)
        
        session.commit()
        print("Default admin user created successfully")
        print("Username: admin")
        print("Password: admin123")
        print("Please change the password after first login")
        
    except Exception as e:
        session.rollback()
        print(f"Error creating default admin user: {e}")
    finally:
        session.close()


