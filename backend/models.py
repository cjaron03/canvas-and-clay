"""Database models for Canvas and Clay application.

Import db from this module after initializing it in app.py.
"""
from datetime import datetime
from flask_login import UserMixin


def init_models(database):
    """Initialize models with the database instance.
    
    Args:
        database: SQLAlchemy database instance from Flask app
        
    Returns:
        User model class
    """
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
        created_at = database.Column(database.DateTime, nullable=False, default=datetime.utcnow)
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
    
    return User
