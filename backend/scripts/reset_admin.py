#!/usr/bin/env python3
"""Emergency Admin Recovery Tool

This script provides a "Skeleton Key" to reset the bootstrap admin password
when recovering from a backup where the original credentials are unknown.

SECURITY: This tool requires physical/SSH access to the server. It cannot
be triggered from the web interface, making it safe from remote attacks.

Usage (from within container):
    python3 scripts/reset_admin.py

Usage (from host via docker):
    docker compose exec backend python3 scripts/reset_admin.py
"""

import getpass
import os
import re
import sys
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from flask_bcrypt import Bcrypt
from models import init_models
from encryption import compute_blind_index, normalize_email
from auth import validate_password as auth_validate_password, is_common_password


def validate_password(password):
    """Validate password meets security requirements including common password check.

    Wraps auth.validate_password() and adds common password blocklist check.
    """
    # Use auth.py's validation (DRY - single source of truth)
    valid, error = auth_validate_password(password)
    if not valid:
        return False, error

    # Additional check: common password blocklist
    if is_common_password(password):
        return False, "Password is too common. Please choose a stronger password."

    return True, None


def update_env_file(new_password):
    """Update BOOTSTRAP_ADMIN_PASSWORD in .env file.

    This ensures the password persists across container restarts.
    """
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')

    if not os.path.exists(env_path):
        print(f"  Warning: .env file not found at {env_path}")
        print("  Password updated in database only. Update .env manually.")
        return False

    try:
        with open(env_path, 'r') as f:
            content = f.read()

        # Replace BOOTSTRAP_ADMIN_PASSWORD line
        if 'BOOTSTRAP_ADMIN_PASSWORD=' in content:
            content = re.sub(
                r'^BOOTSTRAP_ADMIN_PASSWORD=.*$',
                f'BOOTSTRAP_ADMIN_PASSWORD={new_password}',
                content,
                flags=re.MULTILINE
            )
        else:
            # Add if not present
            content += f'\nBOOTSTRAP_ADMIN_PASSWORD={new_password}\n'

        with open(env_path, 'w') as f:
            f.write(content)

        return True
    except Exception as e:
        print(f"  Warning: Could not update .env file: {e}")
        print("  Password updated in database only. Update .env manually.")
        return False


def reset_bootstrap_admin():
    """Emergency tool to reset the Bootstrap Admin password.

    Must be run inside the Docker container or with proper environment setup.
    """
    bcrypt = Bcrypt(app)

    with app.app_context():
        # Get User model (uses caching pattern)
        User, FailedLoginAttempt, AuditLog = init_models(db)

        print()
        print("=" * 60)
        print("       EMERGENCY ADMIN RECOVERY TOOL")
        print("=" * 60)
        print()
        print("This tool resets the bootstrap admin password.")
        print("Use this when recovering from a backup with unknown credentials.")
        print()

        # Get admin email
        default_email = os.getenv('BOOTSTRAP_ADMIN_EMAIL', 'admin@canvas-clay.local')
        email_input = input(f"Admin Email [{default_email}]: ").strip()
        email = email_input if email_input else default_email

        # Look up user via blind index (secure lookup)
        email_idx = compute_blind_index(email, normalizer=normalize_email)
        user = User.query.filter_by(email_idx=email_idx).first()

        if user:
            print(f"\n  Found existing account: {email}")
            print(f"  Role: {user.role}")
            print(f"  Status: {'Active' if user.is_active else 'Inactive'}")

            if user.role != 'admin':
                promote = input("\n  This account is not an admin. Promote to admin? [y/N]: ")
                if promote.lower() == 'y':
                    user.role = 'admin'
                    print("  Account will be promoted to admin.")
                else:
                    print("  Keeping existing role.")
        else:
            print(f"\n  Account '{email}' not found.")
            create = input("  Create new admin account? [Y/n]: ")
            if create.lower() == 'n':
                print("\n  Aborted.")
                return 1

            # Create new admin user
            user = User(
                email=email,
                email_idx=email_idx,
                role='admin',
                is_active=True,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(user)
            print("  New admin account will be created.")

        # Get new password
        print()
        while True:
            new_password = getpass.getpass("New Password: ")
            if not new_password:
                print("  Password cannot be empty.")
                continue

            valid, error = validate_password(new_password)
            if not valid:
                print(f"  {error}")
                continue

            confirm_password = getpass.getpass("Confirm Password: ")
            if new_password != confirm_password:
                print("  Passwords do not match.")
                continue

            break

        # Hash and set password
        user.hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Ensure account is active
        if not user.is_active:
            user.is_active = True
            print("  Account reactivated.")

        # Clear any soft deletion
        if user.deleted_at:
            user.deleted_at = None
            print("  Account restored from deletion.")

        try:
            db.session.commit()
            print()
            print("-" * 60)
            print("  SUCCESS: Password updated in database.")

            # Update .env file for persistence
            if update_env_file(new_password):
                print("  SUCCESS: .env file updated.")

            print("-" * 60)
            print()
            print(f"  You can now log in with:")
            print(f"    Email: {email}")
            print(f"    Password: (the password you just set)")
            print()

            # Create audit log entry
            try:
                from auth import hash_email_for_audit
                audit_log = AuditLog(
                    user_id=user.id,
                    email_hash=hash_email_for_audit(email),
                    event_type='admin_password_recovery',
                    ip_address='127.0.0.1',
                    user_agent='reset_admin.py CLI',
                    details='{"method": "skeleton_key", "source": "cli"}'
                )
                db.session.add(audit_log)
                db.session.commit()
            except Exception as e:
                # Don't fail if audit logging fails
                print(f"  Note: Could not create audit log entry: {e}")

            return 0

        except Exception as e:
            db.session.rollback()
            print()
            print(f"  ERROR: Failed to update password: {e}")
            return 1


if __name__ == "__main__":
    sys.exit(reset_bootstrap_admin())
