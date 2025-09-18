# 🔐 Authentication & Admin System Documentation

## Overview

This is a comprehensive authentication and admin management system built with Flask, featuring:

- **Secure user authentication** with bcrypt password hashing
- **Role-based access control** with granular permissions
- **Modern admin dashboard** with user management
- **Audit logging** for security tracking
- **Beautiful UI** with Tailwind CSS and modern design

## 🚀 Quick Start

### 1. Initialize the Database
```bash
python init_auth_db.py
```

### 2. Validate the System
```bash
python validate_auth.py
```

### 3. Start the Application
```bash
python app.py
```

### 4. Access the System
- **Main Application**: http://localhost:5000
- **Login Page**: http://localhost:5000/auth/login
- **Admin Console**: http://localhost:5000/admin (admin users only)

## 🔑 Default Credentials

**Admin User:**
- Username: `admin`
- Password: `admin123`

⚠️ **Important**: Change the default password after first login!

## 📁 System Architecture

### Core Components

```
auth/
├── __init__.py          # Flask-Login setup
├── models.py            # Database models (User, Permission, etc.)
├── routes.py            # Authentication routes
├── security.py          # Security utilities and decorators
├── permissions.py       # Permission management system
└── database.py          # Database management

admin/
├── __init__.py
└── routes.py            # Admin console routes

templates/
├── auth/                # Authentication templates
│   ├── login.html
│   ├── profile.html
│   ├── register.html
│   └── change_password.html
└── admin/               # Admin console templates
    ├── dashboard.html
    ├── users.html
    ├── permissions.html
    ├── audit_logs.html
    └── settings.html
```

### Database Schema

#### Users Table
- `id` - Primary key
- `username` - Unique username
- `email` - User email
- `password_hash` - Bcrypt hashed password
- `first_name`, `last_name` - User details
- `user_type` - Role (admin, buyer, user)
- `is_admin` - Admin flag
- `is_active` - Account status
- `failed_login_attempts` - Security tracking
- `locked_until` - Account lockout

#### Permissions System
- `permissions` - Available system permissions
- `user_permissions` - User-permission relationships
- `audit_logs` - Security and action logging

## 🛡️ Security Features

### Password Security
- **Bcrypt hashing** with salt
- **Strength requirements**: 8+ chars, uppercase, lowercase, number, special char
- **Account lockout** after 5 failed attempts (30 min lockout)

### Access Control
- **Role-based permissions** (admin, buyer, user)
- **Granular permissions** for specific features
- **Route protection** with decorators
- **Session management** with Flask-Login

### Audit Trail
- **Complete logging** of user actions
- **Security events** tracking
- **IP address** and user agent logging
- **Timestamp** tracking for all events

## 👑 Admin Features

### User Management
- **Create/Edit/Delete** users
- **Activate/Deactivate** accounts
- **Reset passwords**
- **Assign roles** and permissions

### Permission Management
- **Granular permission** control
- **Role-based** default permissions
- **Individual user** permission overrides
- **Permission categories**: upload, view, diagnostic, admin

### System Monitoring
- **Real-time statistics**
- **Audit log** viewing and filtering
- **System status** monitoring
- **User activity** tracking

### Settings Management
- **System configuration**
- **Security settings**
- **Email configuration**
- **Backup management**

## 🎨 UI Features

### Modern Design
- **Tailwind CSS** framework
- **Gradient backgrounds**
- **Glass morphism** effects
- **Smooth animations**
- **Responsive design**

### User Experience
- **Auto-focus** on form fields
- **Password visibility** toggle
- **Flash messages** for feedback
- **Loading states**
- **Error handling**

## 🔧 Configuration

### Environment Variables
```bash
AUTH_DB_URL=sqlite:///auth.db  # Database URL
SECRET_KEY=your-secret-key     # Flask secret key
```

### Permission Categories
- **upload**: File upload permissions
- **view**: Data viewing permissions
- **diagnostic**: System diagnostic access
- **admin**: Administrative functions

### Default Permissions by Role

#### Admin Users
- All permissions (full system access)

#### Buyer Users
- `po_uploader` - Upload PO files
- `batch_management` - Manage batches
- `file_validation` - Validate files
- `dashboard_view` - View dashboard
- `por_search` - Search POR records
- `por_detail` - View POR details

#### Regular Users
- `dashboard_view` - View dashboard
- `por_search` - Search POR records
- `por_detail` - View POR details

## 🚨 Security Best Practices

### For Administrators
1. **Change default passwords** immediately
2. **Use strong passwords** for all accounts
3. **Regularly review** audit logs
4. **Monitor** failed login attempts
5. **Keep permissions** minimal (principle of least privilege)

### For Developers
1. **Never hardcode** credentials
2. **Use environment variables** for sensitive config
3. **Validate all inputs** on server side
4. **Log security events** appropriately
5. **Keep dependencies** updated

## 🔍 Troubleshooting

### Common Issues

#### Database Not Found
```bash
# Reinitialize the database
python init_auth_db.py
```

#### Permission Denied
- Check user permissions in admin console
- Verify user is active
- Check audit logs for security events

#### Login Issues
- Verify credentials
- Check if account is locked
- Review failed login attempts

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📊 Monitoring & Maintenance

### Regular Tasks
- **Review audit logs** weekly
- **Check user activity** monthly
- **Update permissions** as needed
- **Backup database** regularly

### Performance Monitoring
- Monitor login response times
- Check database query performance
- Review memory usage
- Monitor failed login patterns

## 🆕 Future Enhancements

### Planned Features
- **Two-factor authentication** (2FA)
- **Password reset** via email
- **Session timeout** configuration
- **IP whitelisting**
- **Advanced reporting**
- **API authentication** tokens

### Customization Options
- **Custom themes**
- **Branding options**
- **Email templates**
- **Permission templates**
- **Custom user fields**

## 📞 Support

For issues or questions:
1. Check the **audit logs** for error details
2. Review this **documentation**
3. Run the **validation script**
4. Check **Flask logs** for errors

---

**Built with ❤️ for secure, scalable authentication**
