"""
Authentication Package for POR System
Handles user authentication, permissions, and admin console functionality.
"""

from flask_login import LoginManager

# Create a LoginManager instance
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # The route for the login page
login_manager.login_message_category = 'info' # Flash message category

@login_manager.user_loader
def load_user(user_id):
    """User loader function for Flask-Login."""
    from auth.database import get_auth_session
    from auth.models import User
    
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return None

    session = get_auth_session()
    try:
        user = session.query(User).get(user_id)
        return user
    finally:
        session.close()

