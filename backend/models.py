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
            role: User role for RBAC (e.g., 'admin', 'visitor')
            remember_token: Token for "remember me" functionality
            is_active: Whether the account is active (for soft deletion/suspension)
        """
        __tablename__ = 'users'
        
        id = database.Column(database.Integer, primary_key=True)
        email = database.Column(database.String(120), unique=True, nullable=False, index=True)
        hashed_password = database.Column(database.String(128), nullable=False)
        created_at = database.Column(database.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        role = database.Column(database.String(20), nullable=False, default='visitor')
        remember_token = database.Column(database.String(255), unique=True, nullable=True)
        is_active = database.Column(database.Boolean, nullable=False, default=True)
        
        def __repr__(self):
            return f'<User {self.email}>'
        
        def get_id(self):
            """Override UserMixin get_id to return string ID for Flask-Login."""
            return str(self.id)
        
        @property
        def is_admin(self):
            """Check if user has admin role."""
            return self.role == 'admin'
    
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
    
    init_models._models_cache = (User, FailedLoginAttempt, AuditLog)
    return init_models._models_cache
