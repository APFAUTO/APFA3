"""
Authentication models for user management and permissions.
Defines the database schema for users, permissions, and audit logs.
"""

import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from flask_login import UserMixin
from sqlalchemy.pool import StaticPool

# Authentication database configuration
AUTH_DB_URL = os.environ.get('AUTH_DB_URL', "sqlite:///auth.db")

# Create engine for authentication database
auth_engine = create_engine(
    AUTH_DB_URL,
    future=True,
    poolclass=StaticPool,
    pool_pre_ping=True,
    echo=False
)

# Create declarative base
Base = declarative_base()

class User(Base, UserMixin):
    """User model for authentication"""
    __tablename__ = "users"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Basic information
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    
    # User type and permissions
    user_type = Column(String(20), nullable=False)  # 'admin', 'buyer', 'user'
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    force_password_change = Column(Boolean, default=False)
    
    # Relationships
    permissions = relationship("UserPermission", back_populates="user", foreign_keys="[UserPermission.user_id]")
    settings = relationship("UserSetting", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    granted_permissions = relationship("UserPermission", back_populates="granted_by_user", foreign_keys="[UserPermission.granted_by]")
    
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

class Permission(Base):
    """Permission model for feature access control"""
    __tablename__ = "permissions"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Permission details
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)
    category = Column(String(30), nullable=False)  # 'upload', 'view', 'admin', 'diagnostic'
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user_permissions = relationship("UserPermission", back_populates="permission")
    
    def __repr__(self):
        return f"<Permission {self.name}>"

class UserPermission(Base):
    """Many-to-many relationship between users and permissions"""
    __tablename__ = "user_permissions"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign keys
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    
    # Metadata
    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by = Column(Integer, ForeignKey('users.id'))
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="permissions", foreign_keys=[user_id])
    permission = relationship("Permission", back_populates="user_permissions")
    granted_by_user = relationship("User", back_populates="granted_permissions", foreign_keys=[granted_by])
    
    def __repr__(self):
        return f"<UserPermission {self.user_id}:{self.permission_id}>"

class UserSetting(Base):
    """User-specific settings and preferences"""
    __tablename__ = "user_settings"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Setting details
    setting_key = Column(String(50), nullable=False)
    setting_value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="settings")
    
    def __repr__(self):
        return f"<UserSetting {self.user_id}:{self.setting_key}>"

class UserTypeDefaultPermission(Base):
    """Default permissions for user types"""
    __tablename__ = "user_type_default_permissions"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User type and permission
    user_type = Column(String(20), nullable=False)  # 'admin', 'buyer', 'user'
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    permission = relationship("Permission")
    
    def __repr__(self):
        return f"<UserTypeDefaultPermission {self.user_type}:{self.permission_id}>"

class AuditLog(Base):
    """Audit log for tracking user actions and system events"""
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User information
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Action details
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(50))
    
    # Request information
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Timestamp and status
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=True)
    details = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog {self.action} by {self.user_id}>"

# Create indexes for performance
Index('idx_users_username', User.username)
Index('idx_users_email', User.email)
Index('idx_permissions_name', Permission.name)
Index('idx_audit_logs_timestamp', AuditLog.timestamp)
Index('idx_audit_logs_user_id', AuditLog.user_id)

# Create session factory
AuthSessionLocal = sessionmaker(bind=auth_engine)

def get_auth_session():
    """Get a new authentication database session"""
    return AuthSessionLocal()

def create_auth_tables():
    """Create all authentication tables"""
    Base.metadata.create_all(bind=auth_engine)
    print("Authentication database tables created successfully")

def init_default_permissions():
    """Initialize default permissions in the database"""
    session = get_auth_session()
    
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
            ('por_search', 'Search POR records', 'Core'),
            ('por_detail_view', 'View POR details', 'Core'),
            ('diagnostic_views', 'Access diagnostic views', 'Core'),

            # Management Permissions
            ('po_uploader', 'Upload Purchase Order files', 'Management'),
            ('batch_management', 'Manage batch numbers', 'Management'),
            ('file_validation', 'Validate uploaded files', 'Management'),
            ('user_management', 'Manage users', 'Management'),

            # System Permissions
            ('system_settings', 'Modify system settings', 'System'),
            ('audit_logs', 'View audit logs', 'System'),
            ('database_management', 'Manage database settings', 'System'),
            ('company_switching', 'Switch between company databases', 'System'),

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

def create_default_admin_user():
    """Create default admin user if none exists"""
    session = get_auth_session()
    
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

# Initialize database when module is imported
if __name__ == "__main__":
    create_auth_tables()
    init_default_permissions()
    create_default_admin_user()
