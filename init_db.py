import os
from app import create_app, db
from auth.models import UserTypeDefaultPermission, Permission, init_default_permissions, create_default_admin_user

def initialize_database_script():
    app = create_app()
    with app.app_context():
        # Ensure auth.db file exists
        auth_db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace("sqlite:///", "")
        if not os.path.exists(auth_db_path):
            open(auth_db_path, 'a').close()
            print(f"Created empty auth.db at {auth_db_path}")

        print("Calling db.create_all()")
        db.create_all()
        print("db.create_all() called.")

        # Initialize user type defaults if needed (only once)
        existing_defaults = db.session.query(UserTypeDefaultPermission).count()
        if existing_defaults == 0:
            permissions = db.session.query(Permission).all()
            permission_dict = {p.name: p.id for p in permissions}
            
            defaults = {
                'user': ['dashboard_view', 'por_search', 'por_detail'],
                'buyer': ['dashboard_view', 'por_search', 'por_detail', 'po_uploader', 'batch_management', 'file_validation', 'analytics_view'],
                'admin': ['dashboard_view', 'por_search', 'por_detail', 'po_uploader', 'batch_management', 'file_validation', 'analytics_view', 'system_logs', 'database_access', 'user_management', 'system_settings']
            }
            
            for user_type, perm_names in defaults.items():
                for perm_name in perm_names:
                    if perm_name in permission_dict:
                        default_perm = UserTypeDefaultPermission(
                            user_type=user_type,
                            permission_id=permission_dict[perm_name]
                        )
                        db.session.add(default_perm)
            
            db.session.commit()
            print("✅ User type default permissions initialized")
        else:
            print("User type default permissions already exist.")
        
        # Initialize default permissions and admin user
        init_default_permissions(db)
        create_default_admin_user(db)
        
        print("Database initialization script completed.")

if __name__ == "__main__":
    initialize_database_script()
