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


def find_password_reset_by_email(PasswordResetRequest, User, email):
    """Find a password reset request by email using user_id lookup.

    With probabilistic encryption, you cannot query PasswordResetRequest by
    encrypted email directly. This helper finds the user first (using blind
    index), then looks up the reset request by user_id.

    Args:
        PasswordResetRequest: The PasswordResetRequest model class
        User: The User model class
        email: Email address to search for

    Returns:
        PasswordResetRequest object if found, None otherwise
    """
    user = find_user_by_email(User, email)
    if user is None:
        return None
    return PasswordResetRequest.query.filter_by(user_id=user.id).first()


def count_password_resets_by_email(PasswordResetRequest, User, email):
    """Count password reset requests by email using user_id lookup.

    Args:
        PasswordResetRequest: The PasswordResetRequest model class
        User: The User model class
        email: Email address to search for

    Returns:
        Number of password reset requests for this user
    """
    user = find_user_by_email(User, email)
    if user is None:
        return 0
    return PasswordResetRequest.query.filter_by(user_id=user.id).count()


def find_artist_by_email(Artist, email):
    """Find an artist by email using blind index lookup.

    With probabilistic encryption, you cannot query by encrypted email directly.
    This helper computes the blind index and performs the lookup.

    Args:
        Artist: The Artist model class
        email: Email address to search for

    Returns:
        Artist object if found, None otherwise
    """
    if email is None:
        return None
    email_idx = compute_blind_index(email, normalizer=normalize_email)
    return Artist.query.filter_by(artist_email_idx=email_idx).first()


def create_artist_with_index(Artist, db, artist_id, first_name, last_name, email=None, **kwargs):
    """Create an artist with proper artist_email_idx for blind index lookups.

    Args:
        Artist: The Artist model class
        db: SQLAlchemy database instance
        artist_id: Artist ID (8 char)
        first_name: Artist first name
        last_name: Artist last name
        email: Artist email (optional)
        **kwargs: Additional artist fields (artist_site, artist_bio, etc.)

    Returns:
        Created Artist object
    """
    email_idx = None
    if email:
        email_idx = compute_blind_index(email, normalizer=normalize_email)

    artist = Artist(
        artist_id=artist_id,
        artist_fname=first_name,
        artist_lname=last_name,
        artist_email=email,
        artist_email_idx=email_idx,
        **kwargs
    )
    db.session.add(artist)
    return artist
