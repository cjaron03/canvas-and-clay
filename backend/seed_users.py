#!/usr/bin/env python3
"""Seed user accounts from environment variables.

Usage:
    Set environment variables for each user:
        SEED_USER_1_EMAIL=user@example.com
        SEED_USER_1_PASSWORD=SecurePassword123
        SEED_USER_1_ROLE=admin|artist|guest
        SEED_USER_1_ARTIST_ID=ARTS0001  # Optional: links to artist record
        ...

    Then run:
        python3 seed_users.py

    Or use a .env.users file (not tracked in git).

Features:
    - Supports admin, artist, and guest roles
    - Links artist users to Artist records via artist_id
    - Uses upsert pattern (safe to run multiple times)
    - Updates existing users if they exist (email match)
"""

import os
import sys
from datetime import datetime, timezone

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402

# Load from .env.users if it exists (not tracked in git)
env_users_path = os.path.join(os.path.dirname(__file__), '.env.users')
if os.path.exists(env_users_path):
    load_dotenv(env_users_path)

from app import app, db, User, bcrypt  # noqa: E402
from create_tbls import init_tables  # noqa: E402


def get_users_from_env():
    """Load user configurations from environment variables.

    Looks for SEED_USER_N_EMAIL, SEED_USER_N_PASSWORD, SEED_USER_N_ROLE,
    and SEED_USER_N_ARTIST_ID where N is 1, 2, 3, etc.

    Returns:
        list: List of dicts with user configuration
    """
    users = []
    i = 1
    while True:
        email = os.getenv(f'SEED_USER_{i}_EMAIL')
        if not email:
            break

        password = os.getenv(f'SEED_USER_{i}_PASSWORD')
        if not password:
            print(f"Warning: SEED_USER_{i}_EMAIL set but SEED_USER_{i}_PASSWORD missing, skipping")
            i += 1
            continue

        users.append({
            'email': email.strip().lower(),
            'password': password,
            'role': os.getenv(f'SEED_USER_{i}_ROLE', 'guest').strip().lower(),
            'artist_id': os.getenv(f'SEED_USER_{i}_ARTIST_ID', '').strip() or None,
        })
        i += 1

    return users


def upsert_user(user_data, Artist):
    """Create or update a user.

    Args:
        user_data: Dict with email, password, role, artist_id
        Artist: Artist model class

    Returns:
        tuple: (user, was_created, was_updated)
    """
    email = user_data['email']
    password = user_data['password']
    role = user_data['role']
    artist_id = user_data.get('artist_id')

    # Validate role
    valid_roles = ('admin', 'artist', 'guest')
    if role not in valid_roles:
        print(f"  Warning: Invalid role '{role}' for {email}, defaulting to 'guest'")
        role = 'guest'

    # Check if artist exists if artist_id provided
    if artist_id:
        artist = db.session.get(Artist, artist_id)
        if not artist:
            print(f"  Warning: Artist {artist_id} not found, skipping artist link")
            artist_id = None
        elif artist.is_deleted:
            print(f"  Warning: Artist {artist_id} is deleted, skipping artist link")
            artist_id = None

    # Find existing user by email
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        # Update existing user
        updated = False

        if existing_user.role != role:
            existing_user.role = role
            updated = True

        if not bcrypt.check_password_hash(existing_user.hashed_password, password):
            existing_user.hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            updated = True

        if not existing_user.is_active:
            existing_user.is_active = True
            existing_user.deleted_at = None
            updated = True

        # Handle artist link for artist role
        if artist_id and role == 'artist':
            # Unlink any previous artist from this user
            Artist.query.filter_by(user_id=existing_user.id).update({'user_id': None})
            # Link the specified artist
            artist = db.session.get(Artist, artist_id)
            if artist:
                artist.user_id = existing_user.id
                updated = True

        if updated:
            db.session.commit()
            return existing_user, False, True
        return existing_user, False, False

    # Create new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        email=email,
        hashed_password=hashed_password,
        role=role,
        created_at=datetime.now(timezone.utc),
        is_active=True
    )
    db.session.add(new_user)
    db.session.flush()  # Get the user ID

    # Link artist if specified and role is artist
    if artist_id and role == 'artist':
        artist = db.session.get(Artist, artist_id)
        if artist:
            artist.user_id = new_user.id

    db.session.commit()
    return new_user, True, False


def seed_users():
    """Seed users from environment variables."""
    users_config = get_users_from_env()

    if not users_config:
        print("No users configured.")
        print("\nTo seed users, set environment variables:")
        print("  SEED_USER_1_EMAIL=user@example.com")
        print("  SEED_USER_1_PASSWORD=SecurePassword123")
        print("  SEED_USER_1_ROLE=admin|artist|guest")
        print("  SEED_USER_1_ARTIST_ID=ARTS0001  # Optional, for artist role")
        print("\nOr create a .env.users file (not tracked in git).")
        return

    with app.app_context():
        Artist, _, _, _, _, _, _ = init_tables(db)

        created = 0
        updated = 0
        unchanged = 0

        for user_data in users_config:
            try:
                user, was_created, was_updated = upsert_user(user_data, Artist)
                if was_created:
                    print(f"Created {user_data['role']} user: {user_data['email']}")
                    if user_data.get('artist_id'):
                        print(f"  -> Linked to artist: {user_data['artist_id']}")
                    created += 1
                elif was_updated:
                    print(f"Updated user: {user_data['email']}")
                    updated += 1
                else:
                    print(f"Unchanged: {user_data['email']}")
                    unchanged += 1
            except Exception as e:
                print(f"Error processing {user_data['email']}: {e}")
                db.session.rollback()

        print(f"\nSummary: {created} created, {updated} updated, {unchanged} unchanged")


if __name__ == '__main__':
    try:
        seed_users()
    except Exception as e:
        print(f"Error: failed to seed users: {e}")
        sys.exit(1)
