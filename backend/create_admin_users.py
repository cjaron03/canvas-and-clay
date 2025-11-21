"""Script to create admin user accounts.

Usage:
    python create_admin_users.py
"""

import os
import sys
from datetime import datetime, timezone

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, bcrypt  # noqa: E402

# Admin users to create
ADMIN_USERS = [
    {
        'email': 'kiko_barr@gmail.com',
        'password': 'kikobarr'
    },
    {
        'email': 'mckenna_kindle@gmail.com',
        'password': 'mckennakindle'
    },
    {
        'email': 'ashton_bruce@gmail.com',
        'password': 'ashtonbruce'
    }
]


def create_admin_users():
    """Create admin user accounts."""
    with app.app_context():
        created_count = 0
        updated_count = 0
        
        for user_data in ADMIN_USERS:
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
                    print(f"updated user {email} to admin role")
                    updated_count += 1
                else:
                    print(f"user {email} already exists as admin, skipping")
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
                print(f"created admin user: {email}")
                created_count += 1
        
        print(f"\nsummary: created {created_count} new admin(s), updated {updated_count} existing user(s)")


if __name__ == '__main__':
    try:
        create_admin_users()
    except Exception as e:
        print(f"error: failed to create admin users: {e}")
        sys.exit(1)

