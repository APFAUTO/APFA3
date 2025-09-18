#!/usr/bin/env python3
"""
POR Automator Startup Script
Initializes and starts the Flask application with authentication system.
"""

import os
import sys
import webbrowser
import time
from threading import Timer

def print_banner():
    """Print application banner"""
    print("=" * 60)
    print("🚀 POR AUTOMATOR - Authentication System")
    print("=" * 60)
    print("📊 Purchase Order Request Management System")
    print("🔐 With Secure Authentication & Admin Console")
    print("=" * 60)

def check_system():
    """Check system requirements"""
    print("🔍 Checking system requirements...")
    
    # Check if database exists
    if os.path.exists('auth.db'):
        print("✅ Authentication database found")
    else:
        print("⚠️  Authentication database not found, initializing...")
        from auth.database import initialize_auth_database
        initialize_auth_database()
        print("✅ Authentication database created")
    
    # Check if main database exists
    if os.path.exists('a&p_por.db'):
        print("✅ A&P database found")
    else:
        print("✅ A&P database will be created on first run")
    
    print("✅ System check complete!")

def open_browser():
    """Open browser after delay"""
    time.sleep(2)
    print("🌐 Opening browser...")
    webbrowser.open('http://localhost:5000/auth/login')

def main():
    """Main startup function"""
    print_banner()
    check_system()
    
    print("\n🔑 Default Login Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   ⚠️  Please change password after first login!")
    
    print("\n🌐 Application URLs:")
    print("   Login Page:    http://localhost:5000/auth/login")
    print("   Main App:      http://localhost:5000")
    print("   Admin Console: http://localhost:5000/admin")
    
    print("\n🚀 Starting Flask application...")
    print("   Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Start browser timer
    Timer(2.0, open_browser).start()
    
    # Import and start Flask app
    try:
        from app import create_app
        app = create_app()
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
