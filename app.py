
"""
POR Upload Application
A Flask-based system for processing Purchase Order Requests (POR) from Excel files.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, g
from extensions import db

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

    # Configure and initialize Flask-SQLAlchemy for auth.db
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('AUTH_DB_URL', "sqlite:///auth.db")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app) # Initialize db with the app here

    from auth.__init__ import login_manager
    login_manager.init_app(app)

    # Initialize database tables within app context
    with app.app_context():
        # Import models to ensure they are registered with SQLAlchemy
        from auth.models import UserTypeDefaultPermission, Permission, init_default_permissions, create_default_admin_user, create_auth_tables

        # Ensure auth.db file exists
        auth_db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace("sqlite:///", "")
        if not os.path.exists(auth_db_path):
            open(auth_db_path, 'a').close()
            print(f"DEBUG: Created empty auth.db at {auth_db_path}")

        print("DEBUG: Calling db.create_all()")
        db.create_all()
        print("DEBUG: db.create_all() called.")

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
    
    # Add template helper functions for permissions
    from auth.permissions import has_permission, get_user_permissions_for_template
    
    @app.context_processor
    def inject_permission_helpers():
        """Inject permission helper functions into all templates"""
        return {
            'has_permission': has_permission,
            'get_user_permissions': get_user_permissions_for_template
        }
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
