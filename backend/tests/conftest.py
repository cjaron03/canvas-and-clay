"""Shared pytest fixtures and helpers for test suite."""
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from encryption import compute_blind_index, normalize_email


def find_user_by_email(User, email):
    """Find a user by email using blind index lookup.

    With probabilistic encryption, you cannot query by encrypted email directly.
    This helper computes the blind index and performs the lookup.

    Args:
        User: The User model class
        email: Email address to search for

    Returns:
        User object if found, None otherwise
    """
    email_idx = compute_blind_index(email, normalizer=normalize_email)
    return User.query.filter_by(email_idx=email_idx).first()


def create_user_with_index(User, db, bcrypt, email, password, role='guest', is_active=True):
    """Create a user with proper email_idx for blind index lookups.

    Args:
        User: The User model class
        db: SQLAlchemy database instance
        bcrypt: Bcrypt instance for password hashing
        email: User's email address
        password: User's password (will be hashed)
        role: User role (default: 'guest')
        is_active: Whether user is active (default: True)

    Returns:
        Created User object
    """
    from datetime import datetime, timezone

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(
        email=email,
        email_idx=compute_blind_index(email, normalizer=normalize_email),
        hashed_password=hashed,
        role=role,
        is_active=is_active,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(user)
    db.session.commit()
    return user
