#!/usr/bin/env python3
"""
Initialize Authentication Database
Creates the authentication database tables and default admin user.
"""

import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth.database import initialize_auth_database

if __name__ == "__main__":
    print("Starting authentication database initialization...")
    try:
        initialize_auth_database()
        print("✅ Authentication database initialized successfully!")
        print("\nDefault admin user created:")
        print("Username: admin")
        print("Password: admin123")
        print("\nYou can now run the Flask application and test the login system.")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)
