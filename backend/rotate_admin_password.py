"""Utility script to rotate the seeded admin account password.

Usage:
    BOOTSTRAP_ADMIN_PASSWORD="new-strong-password" BOOTSTRAP_ADMIN_EMAIL="admin@example.com" \
    python rotate_admin_password.py

Requires valid app environment (DATABASE_URL, SECRET_KEY, etc.). Fails fast if password is missing.
"""
import os
import sys
from dotenv import load_dotenv

# Load .env first so app picks up env vars
load_dotenv()

from app import app, db, User, BOOTSTRAP_ADMIN_EMAIL, bcrypt  # noqa: E402


def main():
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    if not password:
        print("ERROR: BOOTSTRAP_ADMIN_PASSWORD must be set in the environment.")
        sys.exit(1)

    email = (os.getenv("BOOTSTRAP_ADMIN_EMAIL") or BOOTSTRAP_ADMIN_EMAIL).strip().lower()
    if not email:
        print("ERROR: BOOTSTRAP_ADMIN_EMAIL must be set.")
        sys.exit(1)

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"ERROR: Admin user not found for email {email}")
            sys.exit(1)

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        user.hashed_password = hashed
        # Invalidate any existing remember tokens/sessions
        user.remember_token = None
        db.session.commit()
        print(f"Updated admin password for {email}. Existing sessions will be invalidated.")


if __name__ == "__main__":
    main()
