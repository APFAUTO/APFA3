#!/usr/bin/env python3
"""
Initialize Authentication Database
Creates the authentication database tables and default admin user.
"""

import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from auth.models import init_default_permissions, create_default_admin_user, create_auth_tables

if __name__ == "__main__":
    print("Starting authentication database initialization...")
    app = create_app()
    with app.app_context():
        try:
            create_auth_tables(db) # Ensure tables are created
            init_default_permissions(db) # Initialize default permissions
            create_default_admin_user(db) # Create default admin user
            print("✅ Authentication database initialized successfully!")
            print("\nDefault admin user created:")
            print("Username: admin")
            print("Password: admin123")
            print("\nYou can now run the Flask application and test the login system.")
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            sys.exit(1)
