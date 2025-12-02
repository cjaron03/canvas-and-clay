"""Database models for Canvas and Clay application.

Import db from this module after initializing it in app.py.
"""
from datetime import datetime, timezone
from flask_login import UserMixin


def init_models(database):
    """Initialize models with the database instance.
    
    Args:
        database: SQLAlchemy database instance from Flask app
        
    Returns:
        tuple: (User model class, FailedLoginAttempt model class, AuditLog model class)
    """
    cached_models = getattr(init_models, "_models_cache", None)
    if cached_models is not None:
        return cached_models

    class User(UserMixin, database.Model):
        """User model for authentication and authorization.
        
        Attributes:
            id: Primary key
            email: Unique email address for the user
            hashed_password: Bcrypt hashed password (never store plain text!)
            created_at: Timestamp of account creation
            role: User role for RBAC (e.g., 'admin', 'guest')
            remember_token: Token for "remember me" functionality
            is_active: Whether the account is active (for soft deletion/suspension)
        """
        __tablename__ = 'users'
        
        id = database.Column(database.Integer, primary_key=True)
        email = database.Column(database.String(120), unique=True, nullable=False, index=True)
        hashed_password = database.Column(database.String(128), nullable=False)
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        role = database.Column(database.String(20), nullable=False, default='guest')
        remember_token = database.Column(database.String(255), unique=True, nullable=True)
        is_active = database.Column(database.Boolean, nullable=False, default=True)
        deleted_at = database.Column(database.DateTime, nullable=True)

        # Canonical role ladder (legacy 'visitor' normalized to 'guest')
        ROLE_LADDER = ('guest', 'artist', 'admin')
        LEGACY_ROLE = 'visitor'
        LEGACY_ARTIST_ROLE = 'artist-guest'
        
        def __repr__(self):
            return f'<User {self.email}>'
        
        def get_id(self):
            """Override UserMixin get_id to return string ID for Flask-Login."""
            return str(self.id)
        
        @property
        def normalized_role(self):
            """Get normalized role (with backwards compatibility for legacy values)."""
            if self.role == self.LEGACY_ROLE:
                return 'guest'
            if self.role == self.LEGACY_ARTIST_ROLE:
                return 'artist'
            return self.role

        @property
        def is_admin(self):
            """Check if user has admin role."""
            return self.normalized_role == 'admin'

        @property
        def is_guest(self):
            """Check if user has guest role (includes legacy 'visitor')."""
            return self.normalized_role == 'guest'

        def can_promote(self):
            """Return True if user is not already at the top of the ladder."""
            try:
                return self.ROLE_LADDER.index(self.normalized_role) < len(self.ROLE_LADDER) - 1
            except ValueError:
                return True  # Unknown roles treated as promotable to normalize them

        def can_demote(self):
            """Return True if user is not already at the bottom of the ladder."""
            try:
                return self.ROLE_LADDER.index(self.normalized_role) > 0
            except ValueError:
                return False  # Unknown roles treated as non-demotable until normalized

        def promote(self):
            """Promote user one step up the ladder; no-op if already at top."""
            try:
                idx = self.ROLE_LADDER.index(self.normalized_role)
            except ValueError:
                # Unknown roles normalize to guest before promotion
                self.role = self.ROLE_LADDER[0]
                idx = 0

            if idx < len(self.ROLE_LADDER) - 1:
                self.role = self.ROLE_LADDER[idx + 1]
            return self.normalized_role

        def demote(self):
            """Demote user one step down the ladder; no-op if already at bottom."""
            try:
                idx = self.ROLE_LADDER.index(self.normalized_role)
            except ValueError:
                # Unknown roles normalize to guest before demotion
                self.role = self.ROLE_LADDER[0]
                return self.normalized_role

            if idx > 0:
                self.role = self.ROLE_LADDER[idx - 1]
            return self.normalized_role
    
    class FailedLoginAttempt(database.Model):
        """Model to track failed login attempts for account lockout.
        
        Attributes:
            id: Primary key
            email: Email address that failed login
            ip_address: IP address of the failed attempt
            attempted_at: Timestamp of the failed attempt
            user_agent: User agent string from the request
        """
        __tablename__ = 'failed_login_attempts'
        
        id = database.Column(database.Integer, primary_key=True)
        email = database.Column(database.String(120), nullable=False, index=True)
        ip_address = database.Column(database.String(45), nullable=False, index=True)
        attempted_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
        user_agent = database.Column(database.String(255), nullable=True)
        
        def __repr__(self):
            return f'<FailedLoginAttempt {self.email}@{self.ip_address} at {self.attempted_at}>'
    
    class AuditLog(database.Model):
        """Model for security audit logging.
        
        Attributes:
            id: Primary key
            event_type: Type of event (e.g., 'login_success', 'login_failure', 'account_locked')
            user_id: ID of the user (nullable for failed logins with nonexistent users)
            email: Email address associated with the event
            ip_address: IP address of the request
            user_agent: User agent string from the request
            details: Additional details in JSON format
            created_at: Timestamp of the event
        """
        __tablename__ = 'audit_logs'
        
        id = database.Column(database.Integer, primary_key=True)
        event_type = database.Column(database.String(50), nullable=False, index=True)
        user_id = database.Column(database.Integer, nullable=True, index=True)
        email = database.Column(database.String(120), nullable=True, index=True)
        ip_address = database.Column(database.String(45), nullable=False, index=True)
        user_agent = database.Column(database.String(255), nullable=True)
        details = database.Column(database.Text, nullable=True)  # JSON string for additional details
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
        
        def __repr__(self):
            return f'<AuditLog {self.event_type} for {self.email} at {self.created_at}>'
    
    class PasswordResetRequest(database.Model):
        """Model for manual/admin-assisted password reset workflow."""
        __tablename__ = 'password_reset_requests'

        id = database.Column(database.Integer, primary_key=True)
        user_id = database.Column(database.Integer, database.ForeignKey('users.id'), nullable=True, index=True)
        email = database.Column(database.String(254), nullable=False, index=True)
        status = database.Column(database.String(20), nullable=False, default='pending', index=True)
        user_message = database.Column(database.Text, nullable=True)
        admin_message = database.Column(database.Text, nullable=True)
        reset_code_hash = database.Column(database.String(255), nullable=True)
        reset_code_hint = database.Column(database.String(12), nullable=True)
        approved_by_id = database.Column(database.Integer, database.ForeignKey('users.id'), nullable=True)
        approved_at = database.Column(database.DateTime, nullable=True)
        expires_at = database.Column(database.DateTime, nullable=True)
        resolved_at = database.Column(database.DateTime, nullable=True)
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        updated_at = database.Column(
            database.DateTime,
            nullable=False,
            default=lambda: datetime.now(timezone.utc),
            onupdate=lambda: datetime.now(timezone.utc)
        )

        def __repr__(self):
            return f'<PasswordResetRequest {self.email} #{self.id} ({self.status})>'

    init_models._models_cache = (User, FailedLoginAttempt, AuditLog)
    init_models.PasswordResetRequest = PasswordResetRequest
    return init_models._models_cache
