"""Authentication blueprint for user registration, login, and logout."""
import os
import re
import json as json_lib
import secrets
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from flask_limiter.util import get_remote_address
from functools import wraps
from utils import sanitize_html


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
BOOTSTRAP_ADMIN_EMAIL = (os.getenv('BOOTSTRAP_ADMIN_EMAIL') or 'admin@canvas-clay.local').strip().lower()


def get_dependencies():
    """Get dependencies from app context to avoid circular imports."""
    from app import db, bcrypt, User, FailedLoginAttempt, AuditLog, PasswordResetRequest, limiter
    return db, bcrypt, User, FailedLoginAttempt, AuditLog, PasswordResetRequest, limiter


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


def get_current_role():
    """Get the current user's normalized role.

    Returns:
        str: 'admin', 'guest', or 'anonymous'
    """
    try:
        if current_user.is_authenticated:
            return current_user.normalized_role
        else:
            return 'anonymous'
    except Exception:
        return 'anonymous'


def is_artwork_owner(artwork):
    """Check if the current user owns the given artwork via Artist.user_id.

    Args:
        artwork: Artwork object to check ownership of

    Returns:
        bool: True if current user owns the artwork, False otherwise
    """
    if not current_user.is_authenticated:
        return False

    try:
        # Get the artist associated with this artwork
        from app import db, Artist
        artist = db.session.get(Artist, artwork.artist_id)

        if not artist:
            return False

        # Check if artist is linked to current user
        if artist.user_id and artist.user_id == current_user.id:
            return True

        return False
    except Exception:
        return False


def log_rbac_denial(resource_type, resource_id, reason):
    """Log RBAC denial for audit trail with differentiated reasons.

    Args:
        resource_type: Type of resource (e.g., 'artwork', 'photo')
        resource_id: ID of the resource
        reason: Reason for denial ('insufficient_role' or 'not_owner')
    """
    log_audit_event('rbac_denied',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    email=current_user.email if current_user.is_authenticated else None,
                    details={
                        'resource_type': resource_type,
                        'resource_id': str(resource_id),
                        'reason': reason,
                        'user_role': get_current_role()
                    })


def is_photo_owner(photo):
    """Check if current user owns the photo via artwork ownership.

    Ownership is determined by:
    1. If photo is orphaned (no artwork_num), only admins can modify
    2. If photo belongs to artwork, check if user owns that artwork

    Args:
        photo: ArtworkPhoto object to check ownership of

    Returns:
        bool: True if current user owns the photo's artwork, False otherwise
    """
    if not current_user.is_authenticated:
        return False

    try:
        # Orphaned photos can only be managed by admins
        if photo.artwork_num is None:
            return False

        # Get the artwork this photo belongs to
        from app import db, Artwork
        artwork = db.session.get(Artwork, photo.artwork_num)

        if not artwork:
            return False

        # Check if user owns the artwork
        return is_artwork_owner(artwork)
    except Exception:
        return False


@auth_bp.route('/csrf-token', methods=['GET'])
@rate_limit("100 per minute")  # More lenient limit for frequently-called endpoint
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


def is_common_password(password):
    """Check against a bundled common password list.

    Returns True if the password is in the blocklist.
    """
    try:
        blocklist_path = os.path.join(os.path.dirname(__file__), 'common_passwords.txt')
        if not os.path.exists(blocklist_path):
            return False
        password_lower = password.strip().lower()
        with open(blocklist_path, 'r', encoding='utf-8') as f:
            for line in f:
                if password_lower == line.strip().lower():
                    return True
    except Exception:
        # Fail open if blocklist can't be read
        return False
    return False


def is_user_deleted(user):
    """Return True if user has been soft-deleted."""
    return bool(getattr(user, 'deleted_at', None))


def is_bootstrap_email(email: str) -> bool:
    try:
        return email and email.lower().strip() == BOOTSTRAP_ADMIN_EMAIL
    except Exception:
        return False


@auth_bp.route('/register', methods=['POST'])
@rate_limit("3 per minute")
def register():
    """Register a new user account.

    security: all new user registrations are forced to 'guest' role.
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
    db, bcrypt, User, FailedLoginAttempt, AuditLog, PasswordResetRequest, limiter = get_dependencies()
    
    data = request.get_json()
    
    # Return 400 for both missing data and empty JSON
    if data is None:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # security fix: ignore any client-supplied role parameter
    # all new users are forced to 'guest' role to prevent privilege escalation
    role = 'guest'
    
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

    # Block common passwords
    if is_common_password(password):
        log_audit_event('alert_common_password_blocked', email=email, details={'reason': 'common_password'})
        return jsonify({'error': 'Password is too common. Please choose a stronger password.'}), 400
    
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
                'role': new_user.normalized_role,
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
    db, _, _, _, AuditLog, _, _ = get_dependencies()
    
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
    db, _, _, FailedLoginAttempt, _, _, _ = get_dependencies()
    
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
    db, _, _, FailedLoginAttempt, _, _, _ = get_dependencies()
    
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
        _maybe_alert_failed_login_spike(email)
    except Exception:
        db.session.rollback()


def _maybe_alert_failed_login_spike(email):
    """Log a warning if failed logins spike for a single email or IP in a short window.

    Threshold: >= 3 failures in the last 10 minutes by email or IP.
    """
    from models import init_models
    FailedLoginAttempt = init_models(get_dependencies()[0])[1]

    if not request:
        return

    window_start = datetime.now(timezone.utc) - timedelta(minutes=10)
    ip = get_remote_address()

    email_failures = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.email == email,
        FailedLoginAttempt.attempted_at >= window_start
    ).count()

    ip_failures = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.ip_address == ip,
        FailedLoginAttempt.attempted_at >= window_start
    ).count()

    if email_failures >= 3 or ip_failures >= 3:
        log_audit_event(
            'alert_failed_login_spike',
            email=email,
            details={
                'email_failures_last_10m': email_failures,
                'ip_failures_last_10m': ip_failures,
                'ip_address': ip
            }
        )
        try:
            from app import app as flask_app
            flask_app.logger.warning(
                "Security alert: failed login spike", 
                extra={
                    'email': email,
                    'ip': ip,
                    'email_failures_last_10m': email_failures,
                    'ip_failures_last_10m': ip_failures
                }
            )
        except Exception:
            pass


def clear_failed_login_attempts(email):
    """clear all failed login attempts for an email (on successful login).
    
    Args:
        email: Email address to clear attempts for
    """
    db, _, _, FailedLoginAttempt, _, _, _ = get_dependencies()
    
    try:
        FailedLoginAttempt.query.filter_by(email=email).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()


@auth_bp.route('/login', methods=['POST'])
@rate_limit("20 per 15 minutes")  # Increased for development/testing
def login():
    """Login with email and password.
    
    security features:
    - rate limiting: 20 attempts per 15 minutes per IP address (applied via decorator)
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
    db, bcrypt, User, FailedLoginAttempt, AuditLog, PasswordResetRequest, limiter = get_dependencies()
    
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
        # Normalize lockout timestamp to UTC to avoid naive/aware subtraction issues
        now_utc = datetime.now(timezone.utc)
        if lockout_expires_at.tzinfo is None:
            lockout_expires_at = lockout_expires_at.replace(tzinfo=timezone.utc)
        remaining_time = (lockout_expires_at - now_utc).total_seconds()
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
    
    # check if account is active or soft-deleted
    if not user.is_active or is_user_deleted(user):
        log_audit_event('login_failure', user_id=user.id, email=email, details={
            'reason': 'account_disabled_or_deleted'
        })
        return jsonify({'error': 'Account is disabled or deleted, please contact a Canvas admin to reinstate'}), 403

    # Normalize legacy role values (e.g., 'artist-guest' -> 'artist', 'visitor' -> 'guest')
    canonical_role = user.normalized_role
    if canonical_role != user.role:
        user.role = canonical_role
    
    # successful login - clear failed attempts and log success
    clear_failed_login_attempts(email)
    
    log_audit_event('login_success', user_id=user.id, email=email, details={
        'remember_me': remember
    })
    
    # Issue a fresh session token so admins can forcibly revoke active sessions
    session_token = secrets.token_urlsafe(32)

    # Login user with remember me option (must be called before session modification)
    login_user(user, remember=remember)

    # Persist token on user and in session to detect forced logout
    user.remember_token = session_token
    session['session_token'] = session_token
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Login failed, please try again'}), 500
    
    # Regenerate session to prevent session fixation attacks
    session.permanent = True
    session.modified = True
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.normalized_role
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


@auth_bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Self-service soft delete for the current user."""
    db, _, User, _, AuditLog, _, _ = get_dependencies()

    if is_bootstrap_email(current_user.email):
        return jsonify({'error': 'Cannot delete the bootstrap admin account'}), 403

    try:
        current_user.is_active = False
        current_user.deleted_at = datetime.now(timezone.utc)
        db.session.commit()

        log_audit_event('user_soft_deleted_self', user_id=current_user.id, email=current_user.email)

        logout_user()
        for key in list(session.keys()):
            session.pop(key)
        session.modified = True

        response = jsonify({'message': 'Account scheduled for deletion in 30 days'})
        response.set_cookie('session', '', expires=0, httponly=True, samesite='Lax')
        return response, 200
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete account'}), 500


@auth_bp.route('/me', methods=['GET'])
@rate_limit("100 per minute")  # More lenient limit for frequently-called endpoint
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
            'role': current_user.normalized_role,
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
        'role': current_user.normalized_role
    }), 200


@auth_bp.route('/password-reset/request', methods=['POST'])
@rate_limit("3 per hour")
def request_password_reset():
    """Allow users to file a manual password reset request for admin review."""
    db, _, User, _, _, PasswordResetRequest, _ = get_dependencies()

    data = request.get_json()
    if data is None:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').strip().lower()
    message = (data.get('message') or '').strip()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    is_valid, error_msg = validate_email(email)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # Normalize message and enforce length limit
    cleaned_message = None
    if message:
        cleaned_message = sanitize_html(message)
        if cleaned_message:
            max_len = current_app.config.get('PASSWORD_RESET_MESSAGE_MAX_LENGTH', 500)
            cleaned_message = cleaned_message[:max_len]

    user = User.query.filter_by(email=email).first()

    existing_request = PasswordResetRequest.query.filter(
        PasswordResetRequest.email == email,
        PasswordResetRequest.status.in_(['pending', 'approved'])
    ).order_by(PasswordResetRequest.created_at.desc()).first()

    if existing_request:
        return jsonify({
            'message': 'A reset request is already pending. An admin will contact you soon.'
        }), 200

    new_request = PasswordResetRequest(
        email=email,
        user_id=user.id if user else None,
        user_message=cleaned_message,
        status='pending'
    )

    try:
        db.session.add(new_request)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to record password reset request'}), 500

    log_audit_event(
        'password_reset_requested',
        user_id=user.id if user else None,
        email=email,
        details={'request_id': new_request.id}
    )

    return jsonify({
        'message': 'Request received. An admin will review it shortly.'
    }), 200


@auth_bp.route('/password-reset/verify', methods=['POST'])
@rate_limit("10 per hour")
def verify_reset_code():
    """Verify a reset code without changing the password."""
    db, bcrypt, User, _, _, PasswordResetRequest, _ = get_dependencies()

    data = request.get_json()
    if data is None:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').strip().lower()
    reset_code = (data.get('code') or '').strip()

    if not email or not reset_code:
        return jsonify({'error': 'Email and reset code are required'}), 400

    is_valid_email, error_msg = validate_email(email)
    if not is_valid_email:
        return jsonify({'error': error_msg}), 400

    if len(reset_code) < 4 or len(reset_code) > 64:
        return jsonify({'error': 'Reset code length is invalid'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or reset code'}), 400

    reset_request = PasswordResetRequest.query.filter(
        PasswordResetRequest.email == email,
        PasswordResetRequest.status == 'approved'
    ).order_by(
        PasswordResetRequest.approved_at.desc().nullslast(),
        PasswordResetRequest.created_at.desc()
    ).first()

    if not reset_request or not reset_request.reset_code_hash:
        return jsonify({'error': 'No active reset request found. Please request a new one.'}), 400

    now = datetime.now(timezone.utc)
    if reset_request.expires_at:
        expires_at_aware = reset_request.expires_at
        if expires_at_aware.tzinfo is None:
            expires_at_aware = expires_at_aware.replace(tzinfo=timezone.utc)
        if expires_at_aware <= now:
            reset_request.status = 'expired'
            reset_request.reset_code_hash = None
            reset_request.reset_code_hint = None
            reset_request.expires_at = None
            reset_request.resolved_at = now
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            log_audit_event(
                'password_reset_expired',
                user_id=reset_request.user_id,
                email=reset_request.email,
                details={'request_id': reset_request.id}
            )
            return jsonify({'error': 'Reset code has expired. Please request a new one.'}), 400

    if not bcrypt.check_password_hash(reset_request.reset_code_hash, reset_code):
        log_audit_event(
            'password_reset_code_invalid',
            user_id=reset_request.user_id or user.id,
            email=email,
            details={'request_id': reset_request.id}
        )
        return jsonify({'error': 'Invalid reset code'}), 400

    return jsonify({'message': 'Reset code verified successfully'}), 200


@auth_bp.route('/password-reset/confirm', methods=['POST'])
@rate_limit("5 per hour")
def confirm_password_reset():
    """Redeem an admin-issued reset code and set a new password."""
    db, bcrypt, User, _, _, PasswordResetRequest, _ = get_dependencies()

    data = request.get_json()
    if data is None:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').strip().lower()
    reset_code = (data.get('code') or '').strip()
    new_password = data.get('password', '')

    if not email or not reset_code or not new_password:
        return jsonify({'error': 'Email, reset code, and new password are required'}), 400

    is_valid_email, error_msg = validate_email(email)
    if not is_valid_email:
        return jsonify({'error': error_msg}), 400

    if len(reset_code) < 4 or len(reset_code) > 64:
        return jsonify({'error': 'Reset code length is invalid'}), 400

    is_valid_password, password_error = validate_password(new_password)
    if not is_valid_password:
        return jsonify({'error': password_error}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or reset code'}), 400

    reset_request = PasswordResetRequest.query.filter(
        PasswordResetRequest.email == email,
        PasswordResetRequest.status == 'approved'
    ).order_by(
        PasswordResetRequest.approved_at.desc().nullslast(),
        PasswordResetRequest.created_at.desc()
    ).first()

    if not reset_request or not reset_request.reset_code_hash:
        return jsonify({'error': 'No active reset request found. Please request a new one.'}), 400

    now = datetime.now(timezone.utc)
    if reset_request.expires_at:
        expires_at = reset_request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
        reset_request.status = 'expired'
        reset_request.reset_code_hash = None
        reset_request.reset_code_hint = None
        reset_request.expires_at = None
        reset_request.resolved_at = now
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        log_audit_event(
            'password_reset_expired',
            user_id=reset_request.user_id,
            email=reset_request.email,
            details={'request_id': reset_request.id}
        )
        return jsonify({'error': 'Reset code has expired. Please request a new one.'}), 400

    if not bcrypt.check_password_hash(reset_request.reset_code_hash, reset_code):
        log_audit_event(
            'password_reset_code_invalid',
            user_id=reset_request.user_id or user.id,
            email=email,
            details={'request_id': reset_request.id}
        )
        return jsonify({'error': 'Invalid reset code'}), 400

    try:
        user.hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.remember_token = None
        reset_request.status = 'completed'
        reset_request.reset_code_hash = None
        reset_request.reset_code_hint = None
        reset_request.expires_at = None
        reset_request.resolved_at = now
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update password'}), 500

    # Clear any failed login attempts after successful reset
    try:
        clear_failed_login_attempts(email)
    except Exception:
        pass

    log_audit_event(
        'password_reset_completed',
        user_id=user.id,
        email=email,
        details={'request_id': reset_request.id}
    )

    return jsonify({'message': 'Password updated successfully'}), 200


@auth_bp.route('/change-password', methods=['POST', 'OPTIONS'])
def change_password():
    """Change user's password (requires current password)."""
    if request.method == 'OPTIONS':
        # handle CORS preflight
        return '', 200
    
    # apply decorators manually for POST method
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    db, bcrypt, User, _, _, _, _ = get_dependencies()
    
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not current_password:
        return jsonify({'error': 'Current password is required'}), 400
    
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400
    
    # validate new password
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # block common passwords
    if is_common_password(new_password):
        log_audit_event('alert_common_password_blocked', user_id=current_user.id, email=current_user.email, details={'reason': 'common_password'})
        return jsonify({'error': 'Password is too common. Please choose a stronger password.'}), 400
    
    # verify current password
    if not bcrypt.check_password_hash(current_user.hashed_password, current_password):
        log_audit_event('password_change_failed', user_id=current_user.id, email=current_user.email, details={'reason': 'incorrect_current_password'})
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # check if new password is same as current
    if bcrypt.check_password_hash(current_user.hashed_password, new_password):
        return jsonify({'error': 'New password must be different from current password'}), 400
    
    # update password
    try:
        current_user.hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        # invalidate remember token to force re-login
        current_user.remember_token = None
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update password'}), 500
    
    log_audit_event(
        'password_changed',
        user_id=current_user.id,
        email=current_user.email,
        details={'self_change': True}
    )
    
    return jsonify({'message': 'Password updated successfully'}), 200


@auth_bp.route('/change-email', methods=['POST', 'OPTIONS'])
def change_email():
    """Change user's email address."""
    if request.method == 'OPTIONS':
        # handle CORS preflight
        return '', 200
    
    # apply decorators manually for POST method
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    db, bcrypt, User, _, _, _, _ = get_dependencies()
    
    data = request.get_json(silent=True) or {}
    new_email = data.get('new_email', '').strip().lower()
    password = data.get('password', '').strip()
    
    if not new_email:
        return jsonify({'error': 'New email is required'}), 400
    
    if not password:
        return jsonify({'error': 'Password is required to change email'}), 400
    
    # validate email format
    is_valid, error_msg = validate_email(new_email)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # verify password
    if not bcrypt.check_password_hash(current_user.hashed_password, password):
        log_audit_event('email_change_failed', user_id=current_user.id, email=current_user.email, details={'reason': 'incorrect_password', 'attempted_email': new_email})
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # check if email is already in use
    existing_user = User.query.filter_by(email=new_email).first()
    if existing_user and existing_user.id != current_user.id:
        return jsonify({'error': 'Email address is already in use'}), 400
    
    # check if same email
    if current_user.email.lower() == new_email:
        return jsonify({'error': 'New email must be different from current email'}), 400
    
    old_email = current_user.email
    
    # update email
    try:
        current_user.email = new_email
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update email'}), 500
    
    log_audit_event(
        'email_changed',
        user_id=current_user.id,
        email=old_email,
        details={'old_email': old_email, 'new_email': new_email, 'self_change': True}
    )
    
    return jsonify({
        'message': 'Email updated successfully',
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'role': current_user.normalized_role
        }
    }), 200
