"""
Authentication routes for login, logout, and user management.
"""

import os
from datetime import datetime
from flask import Blueprint, request, render_template, flash, redirect, url_for, session, jsonify
from flask_login import login_user, logout_user

from auth.database import get_auth_session
from auth.models import User, AuditLog
from auth.security import SecurityManager, InputValidator, login_required, admin_required
from auth.permissions import PermissionManager, permission_required

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me', False)
        
        # Validate input
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('auth/login.html')
        
        # Get authentication session
        auth_session = get_auth_session()
        security_manager = SecurityManager(auth_session)
        
        try:
            # Find user
            user = auth_session.query(User).filter(User.username == username).first()
            
            if not user:
                flash('Invalid username or password.', 'error')
                return render_template('auth/login.html')
            
            # Check if account is locked
            is_locked, lock_message = security_manager.is_account_locked(user)
            if is_locked:
                flash(lock_message, 'error')
                return render_template('auth/login.html')
            
            # Check if user is active
            if not user.is_active:
                flash('Account is disabled.', 'error')
                return render_template('auth/login.html')
            
            # Verify password
            if security_manager.verify_password(password, user.password_hash):
                # Successful login
                security_manager.handle_login_attempt(user, True)
                
                # Use Flask-Login's login_user function
                login_user(user, remember=remember_me)
                
                # Set session
                session['user_id'] = user.id
                session['username'] = user.username
                session['user_type'] = user.user_type
                session['is_admin'] = user.is_admin
                session['full_name'] = user.full_name
                
                # Handle remember me
                if remember_me:
                    session.permanent = True
                
                # Log security event
                security_manager.log_security_event(
                    user.id, 'login_success', 'authentication', 
                    success=True, details=f"User {username} logged in successfully"
                )
                
                flash(f'Welcome back, {user.first_name}!', 'success')
                
                # Redirect to intended destination or dashboard
                next_page = request.args.get('next')
                if next_page and security_manager.is_safe_url(next_page):
                    return redirect(next_page)
                
                return redirect(url_for('routes.dashboard'))
            else:
                # Failed login
                security_manager.handle_login_attempt(user, False)
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            flash('An error occurred during login. Please try again.', 'error')
            print(f"Login error: {e}")
        finally:
            auth_session.close()
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    """Handle user logout"""
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Use Flask-Login logout
    logout_user()
    
    # Clear session
    session.clear()
    
    # Log logout event
    if user_id:
        auth_session = get_auth_session()
        security_manager = SecurityManager(auth_session)
        
        try:
            security_manager.log_security_event(
                user_id, 'logout', 'authentication',
                success=True, details=f"User {username} logged out"
            )
        except Exception as e:
            print(f"Logout logging error: {e}")
        finally:
            auth_session.close()
    
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    """Display user profile"""
    auth_session = get_auth_session()
    user = auth_session.query(User).get(session['user_id'])
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.login'))
    
    # Get user permissions
    permission_manager = PermissionManager(auth_session)
    user_permissions = permission_manager.get_user_permissions(user.id)
    
    auth_session.close()
    
    return render_template('auth/profile.html', user=user, permissions=user_permissions)

@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handle password change"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate input
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('auth/change_password.html')
        
        auth_session = get_auth_session()
        security_manager = SecurityManager(auth_session)
        user = auth_session.query(User).get(session['user_id'])
        
        try:
            # Verify current password
            if not security_manager.verify_password(current_password, user.password_hash):
                flash('Current password is incorrect.', 'error')
                return render_template('auth/change_password.html')
            
            # Validate new password strength
            is_strong, message = security_manager.is_password_strong(new_password)
            if not is_strong:
                flash(message, 'error')
                return render_template('auth/change_password.html')
            
            # Update password
            user.password_hash = security_manager.hash_password(new_password)
            user.force_password_change = False
            
            auth_session.commit()
            
            # Log password change
            security_manager.log_security_event(
                user.id, 'password_change', 'authentication',
                success=True, details="Password changed successfully"
            )
            
            flash('Password changed successfully.', 'success')
            return redirect(url_for('auth.profile'))
            
        except Exception as e:
            auth_session.rollback()
            flash('An error occurred while changing password.', 'error')
            print(f"Password change error: {e}")
        finally:
            auth_session.close()
    
    return render_template('auth/change_password.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    """Handle user registration (admin only)"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        user_type = request.form.get('user_type', 'user')
        is_admin = request.form.get('is_admin', False) == 'on'
        
        # Validate input
        if not all([username, email, first_name, last_name, password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')
        
        # Validate email format
        if not InputValidator.validate_email(email):
            flash('Invalid email format.', 'error')
            return render_template('auth/register.html')
        
        auth_session = get_auth_session()
        security_manager = SecurityManager(auth_session)
        permission_manager = PermissionManager(auth_session)
        
        try:
            # Check if username already exists
            existing_user = auth_session.query(User).filter(User.username == username).first()
            if existing_user:
                flash('Username already exists.', 'error')
                return render_template('auth/register.html')
            
            # Check if email already exists
            existing_email = auth_session.query(User).filter(User.email == email).first()
            if existing_email:
                flash('Email already exists.', 'error')
                return render_template('auth/register.html')
            
            # Validate password strength
            is_strong, message = security_manager.is_password_strong(password)
            if not is_strong:
                flash(message, 'error')
                return render_template('auth/register.html')
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password_hash=security_manager.hash_password(password),
                first_name=first_name,
                last_name=last_name,
                user_type=user_type,
                is_admin=is_admin,
                is_active=True
            )
            
            auth_session.add(new_user)
            auth_session.flush()  # Get the user ID
            
            # Grant default permissions based on user type
            success, message = permission_manager.grant_user_type_permissions(new_user.id, user_type)
            if not success:
                flash(f'Error granting permissions: {message}', 'error')
            
            auth_session.commit()
            
            # Log user creation
            security_manager.log_security_event(
                session['user_id'], 'user_creation', 'user_management',
                resource_id=str(new_user.id),
                success=True, details=f"Created user {username} with type {user_type}"
            )
            
            flash(f'User {username} created successfully.', 'success')
            return redirect(url_for('admin.users'))
            
        except Exception as e:
            auth_session.rollback()
            flash('An error occurred while creating user.', 'error')
            print(f"User creation error: {e}")
        finally:
            auth_session.close()
    
    return render_template('auth/register.html')

@auth_bp.route('/check_auth')
def check_auth():
    """Check if user is authenticated (AJAX endpoint)"""
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'username': session.get('username'),
            'user_type': session.get('user_type'),
            'is_admin': session.get('is_admin', False),
            'full_name': session.get('full_name')
        })
    else:
        return jsonify({'authenticated': False})

@auth_bp.route('/session_info')
@login_required
def session_info():
    """Get current session information"""
    auth_session = get_auth_session()
    user = auth_session.query(User).get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    permission_manager = PermissionManager(auth_session)
    user_permissions = permission_manager.get_user_permissions(user.id)
    
    auth_session.close()
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'full_name': user.full_name,
        'user_type': user.user_type,
        'is_admin': user.is_admin,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'permissions': user_permissions
    })
