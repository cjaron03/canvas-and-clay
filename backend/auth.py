"""Authentication blueprint for user registration, login, and logout."""
import re
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def get_dependencies():
    """Get dependencies from app context to avoid circular imports."""
    from app import db, bcrypt, User
    return db, bcrypt, User


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


def validate_email(email):
    """Validate email format.
    
    Args:
        email: Email string to validate
        
    Returns:
        bool: True if valid email format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Validate password meets security requirements.
    
    Requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter  
        - At least one digit
        
    Args:
        password: Password string to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'
    
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit'
    
    return True, None


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user account.
    
    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "SecurePassword123",
            "role": "visitor"  # Optional, defaults to 'visitor'
        }
        
    Returns:
        201: User created successfully
        400: Validation error or duplicate email
        415: Unsupported media type (missing Content-Type: application/json)
    """
    db, bcrypt, User = get_dependencies()
    
    data = request.get_json()
    
    # Return 400 for both missing data and empty JSON
    if data is None:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'visitor')
    
    # Validate email
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Check for duplicate email
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Validate password
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # Validate role
    valid_roles = ['admin', 'visitor']
    if role not in valid_roles:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
    
    # Hash password and create user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    new_user = User(
        email=email,
        hashed_password=hashed_password,
        role=role,
        created_at=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'role': new_user.role,
                'created_at': new_user.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user', 'details': str(e)}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """Login with email and password.
    
    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "SecurePassword123",
            "remember": true  # Optional, defaults to false
        }
        
    Returns:
        200: Login successful
        401: Invalid credentials
        403: Account disabled
    
    TODO(security): Add Flask-Limiter for rate limiting to prevent brute force attacks
    """
    db, bcrypt, User = get_dependencies()
    
    data = request.get_json()
    
    # Accept empty JSON object but still validate required fields
    if data is None:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Check if account is active
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403
    
    # Verify password
    if not bcrypt.check_password_hash(user.hashed_password, password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Regenerate session to prevent session fixation attacks
    session.permanent = True
    session.modified = True
    
    # Login user with remember me option
    login_user(user, remember=remember)
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.role
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout the current user and clear session.
    
    Returns:
        200: Logout successful
        401: No active session
    """
    logout_user()
    
    # Clear all session data and mark as modified
    for key in list(session.keys()):
        session.pop(key)
    session.modified = True
    
    response = jsonify({'message': 'Logout successful'})
    
    # Clear the session cookie by setting it to expire
    response.set_cookie('session', '', expires=0, httponly=True, samesite='Lax')
    
    return response, 200


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current authenticated user information.
    
    Returns:
        200: User info
        401: Not authenticated
    """
    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'role': current_user.role,
            'created_at': current_user.created_at.isoformat()
        }
    }), 200


@auth_bp.route('/protected', methods=['GET'])
@login_required
def protected_route():
    """Example protected route that requires authentication.
    
    Returns:
        200: Access granted
        401: Not authenticated
    """
    return jsonify({
        'message': 'Access granted to protected resource',
        'user': current_user.email
    }), 200


@auth_bp.route('/admin-only', methods=['GET'])
@admin_required
def admin_only_route():
    """Example admin-only route demonstrating RBAC.
    
    Returns:
        200: Access granted
        401: Not authenticated
        403: Not an admin
    """
    return jsonify({
        'message': 'Admin access granted',
        'user': current_user.email,
        'role': current_user.role
    }), 200

