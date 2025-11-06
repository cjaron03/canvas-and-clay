"""Authentication blueprint for user registration, login, and logout."""
import re
import json as json_lib
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from flask_limiter.util import get_remote_address
from functools import wraps


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def get_dependencies():
    """Get dependencies from app context to avoid circular imports."""
    from app import db, bcrypt, User, FailedLoginAttempt, AuditLog, limiter
    return db, bcrypt, User, FailedLoginAttempt, AuditLog, limiter


def rate_limit(limit):
    """Return a limiter decorator that is disabled when TESTING is enabled."""
    def decorator(func):
        from app import limiter, app

        if app.config.get('TESTING', False):
            return func

        return limiter.limit(limit)(func)

    return decorator


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    """get csrf token for frontend requests.
    
    frontend should call this endpoint first to obtain a csrf token,
    then include it in subsequent POST/PUT/DELETE requests via X-CSRFToken header.
    
    Returns:
        200: csrf token in response body
    """
    token = generate_csrf()
    return jsonify({'csrf_token': token}), 200


def validate_email(email):
    """Validate email format and length.
    
    security: enforce maximum length to prevent DoS attacks.
    
    Args:
        email: Email string to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    # RFC 5321: maximum email length is 254 characters
    MAX_EMAIL_LENGTH = 254
    
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f'Email must be no more than {MAX_EMAIL_LENGTH} characters'
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, 'Invalid email format'
    
    return True, None


def validate_password(password):
    """Validate password meets security requirements.
    
    security: enforce length limits to prevent DoS attacks.
    
    Requirements:
        - Minimum 8 characters
        - Maximum 128 characters
        - At least one uppercase letter
        - At least one lowercase letter  
        - At least one digit
        
    Args:
        password: Password string to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f'Password must be no more than {MAX_PASSWORD_LENGTH} characters'
    
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit'
    
    return True, None


@auth_bp.route('/register', methods=['POST'])
@rate_limit("3 per minute")
def register():
    """Register a new user account.
    
    security: all new user registrations are forced to 'visitor' role.
    admin role must be granted through admin promotion endpoint.
    
    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "SecurePassword123"
        }
        
    Returns:
        201: User created successfully
        400: Validation error or duplicate email
        415: Unsupported media type (missing Content-Type: application/json)
    """
    db, bcrypt, User, FailedLoginAttempt, AuditLog, limiter = get_dependencies()
    
    data = request.get_json()
    
    # Return 400 for both missing data and empty JSON
    if data is None:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # security fix: ignore any client-supplied role parameter
    # all new users are forced to 'visitor' role to prevent privilege escalation
    role = 'visitor'
    
    # Validate email
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    is_valid, error_msg = validate_email(email)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # Check for duplicate email
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Validate password
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
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
        # security fix: don't expose internal error details to client
        return jsonify({'error': 'Failed to create user'}), 500


def log_audit_event(event_type, user_id=None, email=None, details=None):
    """log security audit event.
    
    Args:
        event_type: Type of event (e.g., 'login_success', 'login_failure', 'account_locked')
        user_id: ID of the user (optional)
        email: Email address associated with the event (optional)
        details: Additional details as dict (will be JSON serialized)
    """
    db, _, _, _, AuditLog, _ = get_dependencies()
    
    ip_address = get_remote_address()
    user_agent = request.headers.get('User-Agent', '')
    details_json = json_lib.dumps(details) if details else None
    
    audit_log = AuditLog(
        event_type=event_type,
        user_id=user_id,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details_json,
        created_at=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(audit_log)
        db.session.commit()
    except Exception:
        # silently fail audit logging to prevent breaking authentication flow
        db.session.rollback()


def check_account_locked(email):
    """check if account is locked due to too many failed login attempts.
    
    Args:
        email: Email address to check
        
    Returns:
        tuple: (is_locked: bool, lockout_expires_at: datetime or None)
    """
    db, _, _, FailedLoginAttempt, _, _ = get_dependencies()
    
    # check failed attempts in last 15 minutes
    lockout_window = datetime.now(timezone.utc) - timedelta(minutes=15)
    recent_failures = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.email == email,
        FailedLoginAttempt.attempted_at >= lockout_window
    ).order_by(FailedLoginAttempt.attempted_at.desc()).all()
    
    if len(recent_failures) >= 5:
        # account is locked - return lockout expiration (15 min from first failure in window)
        first_failure = recent_failures[-1]
        lockout_expires_at = first_failure.attempted_at + timedelta(minutes=15)
        return True, lockout_expires_at
    
    return False, None


def record_failed_login(email):
    """record a failed login attempt.
    
    Args:
        email: Email address that failed login
    """
    db, _, _, FailedLoginAttempt, _, _ = get_dependencies()
    
    ip_address = get_remote_address()
    user_agent = request.headers.get('User-Agent', '')
    
    failed_attempt = FailedLoginAttempt(
        email=email,
        ip_address=ip_address,
        attempted_at=datetime.now(timezone.utc),
        user_agent=user_agent
    )
    
    try:
        db.session.add(failed_attempt)
        db.session.commit()
    except Exception:
        db.session.rollback()


def clear_failed_login_attempts(email):
    """clear all failed login attempts for an email (on successful login).
    
    Args:
        email: Email address to clear attempts for
    """
    db, _, _, FailedLoginAttempt, _, _ = get_dependencies()
    
    try:
        FailedLoginAttempt.query.filter_by(email=email).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()


@auth_bp.route('/login', methods=['POST'])
@rate_limit("5 per 15 minutes")
def login():
    """Login with email and password.
    
    security features:
    - rate limiting: 5 attempts per 15 minutes per IP address (applied via decorator)
    - account lockout: 5 failed attempts per email = 15 minute lockout
    - audit logging: all login attempts (success and failure) are logged
    
    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "SecurePassword123",
            "remember": true  # Optional, defaults to false
        }
        
    Returns:
        200: Login successful
        429: Rate limit exceeded
        401: Invalid credentials
        403: Account disabled or locked
    """
    db, bcrypt, User, FailedLoginAttempt, AuditLog, limiter = get_dependencies()
    
    data = request.get_json()
    
    # Accept empty JSON object but still validate required fields
    if data is None:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    # validate email length (DoS prevention)
    is_valid, error_msg = validate_email(email)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # validate password length (DoS prevention)
    MAX_PASSWORD_LENGTH = 128
    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({'error': f'Password must be no more than {MAX_PASSWORD_LENGTH} characters'}), 400
    
    # check account lockout (check before user lookup to prevent user enumeration)
    is_locked, lockout_expires_at = check_account_locked(email)
    if is_locked:
        remaining_time = (lockout_expires_at - datetime.now(timezone.utc)).total_seconds()
        log_audit_event('account_locked', email=email, details={
            'lockout_expires_at': lockout_expires_at.isoformat(),
            'remaining_seconds': int(remaining_time)
        })
        return jsonify({
            'error': 'Account temporarily locked due to too many failed login attempts. Please try again later.'
        }), 403
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    
    # verify password (or return generic error if user doesn't exist)
    password_valid = False
    if user:
        password_valid = bcrypt.check_password_hash(user.hashed_password, password)
    
    if not user or not password_valid:
        # record failed login attempt
        record_failed_login(email)
        
        # log failed login attempt
        log_audit_event('login_failure', email=email, details={
            'reason': 'invalid_credentials'
        })
        
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # check if account is active
    if not user.is_active:
        log_audit_event('login_failure', user_id=user.id, email=email, details={
            'reason': 'account_disabled'
        })
        return jsonify({'error': 'Account is disabled'}), 403
    
    # successful login - clear failed attempts and log success
    clear_failed_login_attempts(email)
    
    log_audit_event('login_success', user_id=user.id, email=email, details={
        'remember_me': remember
    })
    
    # Login user with remember me option (must be called before session modification)
    login_user(user, remember=remember)
    
    # Regenerate session to prevent session fixation attacks
    session.permanent = True
    session.modified = True
    
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
