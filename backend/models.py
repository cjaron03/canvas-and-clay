"""Database models for Canvas and Clay application.

Import db from this module after initializing it in app.py.
"""
from datetime import datetime, timezone
from flask_login import UserMixin

from encryption import EncryptedString, normalize_email, compute_blind_index


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

        # Default upload quota: 500MB per user
        DEFAULT_UPLOAD_QUOTA = 500 * 1024 * 1024  # 500MB in bytes

        id = database.Column(database.Integer, primary_key=True)
        # Email is encrypted with random nonce (probabilistic) - use email_idx for lookups
        email = database.Column(EncryptedString(255, normalizer=normalize_email), nullable=False)
        # Blind index for email lookups (HMAC-based, allows searching without revealing patterns)
        email_idx = database.Column(database.String(64), unique=True, nullable=False, index=True)
        hashed_password = database.Column(database.String(128), nullable=False)
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        role = database.Column(database.String(20), nullable=False, default='guest')
        remember_token = database.Column(database.String(255), unique=True, nullable=True)
        is_active = database.Column(database.Boolean, nullable=False, default=True)
        deleted_at = database.Column(database.DateTime, nullable=True)

        # Upload quota tracking (disk exhaustion protection)
        upload_quota_bytes = database.Column(
            database.BigInteger,
            nullable=False,
            default=DEFAULT_UPLOAD_QUOTA
        )
        bytes_uploaded = database.Column(database.BigInteger, nullable=False, default=0)

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

        # Upload quota methods
        @property
        def quota_remaining(self):
            """Return remaining upload quota in bytes."""
            return max(0, self.upload_quota_bytes - self.bytes_uploaded)

        @property
        def quota_used_percent(self):
            """Return percentage of quota used (0-100)."""
            if self.upload_quota_bytes <= 0:
                return 100.0
            return min(100.0, (self.bytes_uploaded / self.upload_quota_bytes) * 100)

        def can_upload(self, file_size_bytes):
            """Check if user can upload a file of given size.

            Args:
                file_size_bytes: Size of file to upload in bytes

            Returns:
                bool: True if upload would be within quota
            """
            # Admins have unlimited quota
            if self.is_admin:
                return True
            return self.bytes_uploaded + file_size_bytes <= self.upload_quota_bytes

        def record_upload(self, file_size_bytes):
            """Record an upload against user's quota.

            Args:
                file_size_bytes: Size of uploaded file in bytes
            """
            self.bytes_uploaded = (self.bytes_uploaded or 0) + file_size_bytes

        def record_deletion(self, file_size_bytes):
            """Record a file deletion to reclaim quota.

            Args:
                file_size_bytes: Size of deleted file in bytes
            """
            self.bytes_uploaded = max(0, (self.bytes_uploaded or 0) - file_size_bytes)

        # Email blind index helpers
        @staticmethod
        def compute_email_index(email):
            """Compute the blind index for an email address.

            Args:
                email: Raw email string

            Returns:
                64-character hex string for email_idx column
            """
            return compute_blind_index(email, normalizer=normalize_email)

        def update_email(self, new_email):
            """Update user's email and its blind index.

            Args:
                new_email: New email address
            """
            self.email = new_email
            self.email_idx = self.compute_email_index(new_email)

    class FailedLoginAttempt(database.Model):
        """Model to track failed login attempts for account lockout.

        Attributes:
            id: Primary key
            email: Email address that failed login
            ip_address: IP address of the failed attempt
            attempted_at: Timestamp of the failed attempt
            user_agent: User agent string from the request

        SECURITY NOTE: email is intentionally NOT encrypted here because:
        - Rate limiting requires fast, searchable lookups by email
        - These records have short retention (cleaned up after lockout window)
        - The threat model prioritizes operational security over data-at-rest protection
        """
        __tablename__ = 'failed_login_attempts'

        id = database.Column(database.Integer, primary_key=True)
        # Intentionally unencrypted - see class docstring for rationale
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

        SECURITY NOTE: email is intentionally NOT encrypted here because:
        - Security investigations require searchable audit trails
        - Compliance requirements may mandate plaintext audit records
        - Audit logs should remain readable even if encryption keys are rotated
        """
        __tablename__ = 'audit_logs'

        id = database.Column(database.Integer, primary_key=True)
        event_type = database.Column(database.String(50), nullable=False, index=True)
        user_id = database.Column(database.Integer, nullable=True, index=True)
        # Intentionally unencrypted - see class docstring for rationale
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
        email = database.Column(EncryptedString(255, normalizer=normalize_email), nullable=False, index=True)
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

    class UserSession(database.Model):
        """Model for tracking individual user sessions across devices.

        Enables multi-account sign-in by storing session tokens per-device
        instead of a single global remember_token on the User model.

        Attributes:
            id: Primary key (64-char hex string)
            user_id: Foreign key to users table
            session_token: Unique token for session validation
            user_agent: Browser/device information
            ip_address: IP address of session origin
            created_at: When the session was created
            last_active_at: Last request timestamp (for session activity)
            expires_at: When the session expires (nullable for non-remember sessions)
            is_active: Whether session is valid (for admin force-logout)
        """
        __tablename__ = 'user_sessions'

        id = database.Column(database.String(64), primary_key=True)
        user_id = database.Column(
            database.Integer,
            database.ForeignKey('users.id', ondelete='CASCADE'),
            nullable=False,
            index=True
        )
        session_token = database.Column(database.String(255), nullable=False, unique=True, index=True)
        user_agent = database.Column(database.String(500), nullable=True)
        ip_address = database.Column(database.String(45), nullable=True)
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        last_active_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        expires_at = database.Column(database.DateTime, nullable=True)
        is_active = database.Column(database.Boolean, nullable=False, default=True)

        # Relationship to User
        user = database.relationship('User', backref=database.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))

        def __repr__(self):
            return f'<UserSession {self.id[:8]}... user_id={self.user_id}>'

        def is_expired(self):
            """Check if session has expired."""
            if self.expires_at is None:
                return False
            # Handle both naive and aware datetimes from database
            expires = self.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > expires

        def is_valid(self):
            """Check if session is both active and not expired."""
            return self.is_active and not self.is_expired()

        def touch(self):
            """Update last_active_at to current time."""
            self.last_active_at = datetime.now(timezone.utc)

    class LegalPage(database.Model):
        """Model for storing editable legal pages (privacy policy, terms of service).

        Attributes:
            id: Primary key
            page_type: Type identifier (e.g., 'privacy_policy', 'terms_of_service')
            title: Display title of the page
            content: HTML content of the page
            last_updated: Timestamp of last update
            updated_by: User ID of admin who last updated
        """
        __tablename__ = 'legal_pages'

        id = database.Column(database.Integer, primary_key=True)
        page_type = database.Column(database.String(50), nullable=False, unique=True, index=True)
        title = database.Column(database.String(255), nullable=False)
        content = database.Column(database.Text, nullable=False)
        last_updated = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        updated_by = database.Column(database.Integer, database.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

        # Relationship to User for displaying editor name
        editor = database.relationship('User', foreign_keys=[updated_by])

        def __repr__(self):
            return f'<LegalPage {self.page_type}>'

    init_models._models_cache = (User, FailedLoginAttempt, AuditLog)
    init_models.PasswordResetRequest = PasswordResetRequest
    init_models.UserSession = UserSession
    init_models.LegalPage = LegalPage
    return init_models._models_cache
