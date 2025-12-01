"""Script to create admin user accounts from environment variables.

Usage:
    Set environment variables for each admin user:
        ADMIN_USER_1_EMAIL=admin1@example.com
        ADMIN_USER_1_PASSWORD=SecurePassword123
        ADMIN_USER_2_EMAIL=admin2@example.com
        ADMIN_USER_2_PASSWORD=SecurePassword456
        ...

    Then run:
        python create_admin_users.py

    Alternatively, create a .env.admins file (not tracked in git) with the variables.
"""

import os
import sys
from datetime import datetime, timezone

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402

# Load admin credentials from .env.admins if it exists (not tracked in git)
env_admins_path = os.path.join(os.path.dirname(__file__), '.env.admins')
if os.path.exists(env_admins_path):
    load_dotenv(env_admins_path)

from app import app, db, User, bcrypt  # noqa: E402


def get_admin_users_from_env():
    """Load admin user credentials from environment variables.

    Looks for ADMIN_USER_N_EMAIL and ADMIN_USER_N_PASSWORD pairs
    where N is 1, 2, 3, etc.

    Returns:
        list: List of dicts with 'email' and 'password' keys
    """
    admin_users = []
    i = 1
    while True:
        email = os.getenv(f'ADMIN_USER_{i}_EMAIL')
        password = os.getenv(f'ADMIN_USER_{i}_PASSWORD')

        if not email:
            break

        if not password:
            print(f"Warning: ADMIN_USER_{i}_EMAIL is set but ADMIN_USER_{i}_PASSWORD is missing, skipping")
            i += 1
            continue

        admin_users.append({
            'email': email,
            'password': password
        })
        i += 1

    return admin_users


def create_admin_users():
    """Create admin user accounts from environment variables."""
    admin_users = get_admin_users_from_env()

    if not admin_users:
        print("No admin users configured.")
        print("\nTo create admin users, set environment variables:")
        print("  ADMIN_USER_1_EMAIL=admin@example.com")
        print("  ADMIN_USER_1_PASSWORD=SecurePassword123")
        print("\nOr create a .env.admins file (not tracked in git) with these variables.")
        return

    with app.app_context():
        created_count = 0
        updated_count = 0

        for user_data in admin_users:
            email = user_data['email'].strip().lower()
            password = user_data['password']

            # check if user already exists
            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                # update existing user to admin if not already
                if existing_user.role != 'admin':
                    existing_user.role = 'admin'
                    # update password if needed
                    if not bcrypt.check_password_hash(existing_user.hashed_password, password):
                        existing_user.hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    existing_user.is_active = True
                    existing_user.deleted_at = None
                    db.session.commit()
                    print(f"Updated user {email} to admin role")
                    updated_count += 1
                else:
                    print(f"User {email} already exists as admin, skipping")
            else:
                # create new admin user
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(
                    email=email,
                    hashed_password=hashed_password,
                    role='admin',
                    created_at=datetime.now(timezone.utc),
                    is_active=True
                )
                db.session.add(new_user)
                db.session.commit()
                print(f"Created admin user: {email}")
                created_count += 1

        print(f"\nSummary: created {created_count} new admin(s), updated {updated_count} existing user(s)")


if __name__ == '__main__':
    try:
        create_admin_users()
    except Exception as e:
        print(f"Error: failed to create admin users: {e}")
        sys.exit(1)
