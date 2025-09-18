#!/usr/bin/env python3
"""
Authentication System Validation Script
Tests the login and admin system functionality.
"""

import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_database_initialization():
    """Test database initialization"""
    print("🔍 Testing database initialization...")
    try:
        from auth.database import initialize_auth_database
        initialize_auth_database()
        print("✅ Database initialization successful!")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def test_user_creation():
    """Test user creation and authentication"""
    print("\n🔍 Testing user creation...")
    try:
        from auth.database import get_auth_session
        from auth.models import User
        from auth.security import SecurityManager
        
        session = get_auth_session()
        security_manager = SecurityManager(session)
        
        # Check if admin user exists
        admin_user = session.query(User).filter(User.username == 'admin').first()
        if admin_user:
            print("✅ Admin user exists!")
            
            # Test password verification
            if security_manager.verify_password('admin123', admin_user.password_hash):
                print("✅ Password verification works!")
            else:
                print("❌ Password verification failed!")
                return False
        else:
            print("❌ Admin user not found!")
            return False
            
        session.close()
        return True
    except Exception as e:
        print(f"❌ User creation test failed: {e}")
        return False

def test_permissions():
    """Test permission system"""
    print("\n🔍 Testing permission system...")
    try:
        from auth.database import get_auth_session
        from auth.models import Permission
        from auth.permissions import PermissionManager
        
        session = get_auth_session()
        permission_manager = PermissionManager(session)
        
        # Check if permissions exist
        permissions = session.query(Permission).count()
        if permissions > 0:
            print(f"✅ Found {permissions} permissions!")
            
            # Test permission checking for admin user
            admin_has_permission = permission_manager.check_permission(1, 'user_management')
            if admin_has_permission:
                print("✅ Admin permission checking works!")
            else:
                print("❌ Admin permission checking failed!")
                return False
        else:
            print("❌ No permissions found!")
            return False
            
        session.close()
        return True
    except Exception as e:
        print(f"❌ Permission test failed: {e}")
        return False

def test_flask_app():
    """Test Flask app creation"""
    print("\n🔍 Testing Flask app creation...")
    try:
        from app import create_app
        app = create_app()
        
        if app:
            print("✅ Flask app created successfully!")
            
            # Test blueprints are registered
            blueprint_names = [bp.name for bp in app.blueprints.values()]
            expected_blueprints = ['routes', 'auth', 'admin']
            
            for bp in expected_blueprints:
                if bp in blueprint_names:
                    print(f"✅ Blueprint '{bp}' registered!")
                else:
                    print(f"❌ Blueprint '{bp}' missing!")
                    return False
            
            return True
        else:
            print("❌ Flask app creation failed!")
            return False
    except Exception as e:
        print(f"❌ Flask app test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Authentication System Validation\n")
    
    tests = [
        test_database_initialization,
        test_user_creation,
        test_permissions,
        test_flask_app
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your authentication system is ready!")
        print("\n🔑 Default Login Credentials:")
        print("Username: admin")
        print("Password: admin123")
        print("\n🌐 To start the application, run:")
        print("python app.py")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
