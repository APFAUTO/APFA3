"""
Authentication database management.
Handles database connections and session management for authentication.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth.models import Base, get_auth_session

class AuthDatabaseManager:
    """Manages authentication database connections and sessions"""
    
    def __init__(self, db_url=None):
        """Initialize authentication database manager"""
        self.db_url = db_url or os.environ.get('AUTH_DB_URL', "sqlite:///auth.db")
        
        # Create engine with optimized settings
        self.engine = create_engine(
            self.db_url,
            future=True,
            connect_args={'timeout': 15},
            echo=False
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        print(f"Authentication database manager initialized: {self.db_url}")
    
    def create_tables(self):
        """Create all authentication tables"""
        import logging
        logging.info("Creating authentication tables...")
        Base.metadata.create_all(bind=self.engine)
        logging.info("Authentication tables created successfully")
        print("Authentication tables created successfully")
    
    def get_session(self):
        """Get a new database session"""
        return self.SessionLocal()
    
    def close_session(self, session):
        """Close database session"""
        if session:
            session.close()
    
    def execute_raw_sql(self, sql, params=None):
        """Execute raw SQL query"""
        session = self.get_session()
        try:
            result = session.execute(sql, params or {})
            return result.fetchall()
        except Exception as e:
            print(f"Error executing SQL: {e}")
            return None
        finally:
            self.close_session(session)
    
    def backup_database(self, backup_path):
        """Create backup of authentication database"""
        try:
            import shutil
            shutil.copy2(self.db_url.replace('sqlite:///', ''), backup_path)
            print(f"Database backed up to: {backup_path}")
            return True
        except Exception as e:
            print(f"Error backing up database: {e}")
            return False
    
    def restore_database(self, backup_path):
        """Restore database from backup"""
        try:
            import shutil
            shutil.copy2(backup_path, self.db_url.replace('sqlite:///', ''))
            print(f"Database restored from: {backup_path}")
            return True
        except Exception as e:
            print(f"Error restoring database: {e}")
            return False
    
    def get_database_stats(self):
        """Get database statistics"""
        session = self.get_session()
        try:
            from auth.models import User, Permission, UserPermission, AuditLog
            
            stats = {
                'users': session.query(User).count(),
                'active_users': session.query(User).filter(User.is_active == True).count(),
                'permissions': session.query(Permission).count(),
                'user_permissions': session.query(UserPermission).count(),
                'audit_logs': session.query(AuditLog).count(),
                'locked_accounts': session.query(User).filter(User.locked_until.isnot(None)).count()
            }
            
            return stats
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {}
        finally:
            self.close_session(session)

# Global instance for easy access
auth_db_manager = AuthDatabaseManager()

def initialize_auth_database():
    """Initialize authentication database with tables and default data"""
    print("Initializing authentication database...")
    import logging
    logging.info("Initializing authentication database...")
    
    # Create tables
    auth_db_manager.create_tables()
    
    # Initialize default permissions
    from auth.models import init_default_permissions, create_default_admin_user
    init_default_permissions()
    create_default_admin_user()
    
    logging.info("Authentication database initialized successfully")
    print("Authentication database initialized successfully")

if __name__ == "__main__":
    initialize_auth_database()
