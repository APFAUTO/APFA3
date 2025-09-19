#!/usr/bin/env python3
"""
Initialize User Type Default Permissions
Creates the new table and sets up default permissions for each user type.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth.models import get_auth_session, Permission, UserTypeDefaultPermission, create_auth_tables

def initialize_user_type_defaults():
    """Initialize user type default permissions"""
    print("🔧 Initializing User Type Default Permissions...")
    
    # Create tables if they don't exist
    create_auth_tables()
    
    session = get_auth_session()
    
    try:
        # Check if we already have defaults
        existing_defaults = session.query(UserTypeDefaultPermission).count()
        if existing_defaults > 0:
            print("✅ User type defaults already exist!")
            return
        
        # Get all permissions
        permissions = session.query(Permission).all()
        permission_dict = {p.name: p.id for p in permissions}
        
        # Define default permissions for each user type
        defaults = {
            'user': [
                'dashboard_view',
                'por_search',
                'por_detail'
            ],
            'buyer': [
                'dashboard_view',
                'por_search',
                'por_detail',
                'po_uploader',
                'batch_management',
                'file_validation',
                'analytics_view'
            ],
            'admin': [
                'dashboard_view',
                'por_search',
                'por_detail',
                'po_uploader',
                'batch_management',
                'file_validation',
                'analytics_view',
                'system_logs',
                'database_access',
                'user_management',
                'system_settings'
            ]
        }
        
        # Create default permissions for each user type
        for user_type, perm_names in defaults.items():
            print(f"📝 Setting up defaults for {user_type} users...")
            
            for perm_name in perm_names:
                if perm_name in permission_dict:
                    default_perm = UserTypeDefaultPermission(
                        user_type=user_type,
                        permission_id=permission_dict[perm_name]
                    )
                    session.add(default_perm)
                else:
                    print(f"⚠️  Permission '{perm_name}' not found, skipping...")
        
        session.commit()
        print("✅ User type default permissions initialized successfully!")
        
        # Display summary
        print("\n📊 Summary of Default Permissions:")
        for user_type in ['user', 'buyer', 'admin']:
            count = session.query(UserTypeDefaultPermission).filter(
                UserTypeDefaultPermission.user_type == user_type
            ).count()
            print(f"   {user_type.capitalize()}: {count} permissions")
        
    except Exception as e:
        print(f"❌ Error initializing user type defaults: {e}")
        session.rollback()
        return False
    
    finally:
        session.close()
    
    return True

if __name__ == "__main__":
    success = initialize_user_type_defaults()
    if success:
        print("\n🎉 User type defaults initialization complete!")
        print("You can now configure default permissions for each user type in the admin console.")
    else:
        print("\n💥 Initialization failed!")
        sys.exit(1)
