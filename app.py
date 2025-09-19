
"""
POR Upload Application
A Flask-based system for processing Purchase Order Requests (POR) from Excel files.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, g
from auth.database import initialize_auth_database

# Setup logging
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

# File handler
file_handler = RotatingFileHandler('logs.txt', maxBytes=10240, backupCount=10)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.ERROR)

# Get root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def create_app():
    # Flask app setup
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    
    # Force template reloading
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    
    app.config.update(
        UPLOAD_FOLDER="static/uploads",
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
        SECRET_KEY='a-very-secret-key',  # Hardcoded for consistency
    )

    from auth.__init__ import login_manager
    login_manager.init_app(app)

    # Initialize database once at startup
    def initialize_database():
        if not os.path.exists('auth.db'):
            initialize_auth_database()
        
        # Initialize user type defaults if needed (only once)
        from auth.models import get_auth_session, UserTypeDefaultPermission, Permission
        auth_session = get_auth_session()
        try:
            # Check if defaults exist
            existing_defaults = auth_session.query(UserTypeDefaultPermission).count()
            if existing_defaults == 0:
                # Initialize with default permissions
                permissions = auth_session.query(Permission).all()
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
                            auth_session.add(default_perm)
                
                auth_session.commit()
                print("✅ User type default permissions initialized")
        except Exception as e:
            print(f"⚠️ Error initializing user type defaults: {e}")
            auth_session.rollback()
        finally:
            auth_session.close()
    
    # Run initialization once at startup
    initialize_database()

    # Add cache-busting headers to all responses
    @app.after_request
    def add_cache_headers(response):
        """Add cache-busting headers to prevent browser caching."""
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    from routes import routes
    app.register_blueprint(routes)
    
    # Import and register auth blueprint
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    # Import and register admin blueprint
    from admin.routes import admin_bp
    app.register_blueprint(admin_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
