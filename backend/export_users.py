#!/usr/bin/env python3
"""Export users to a portable JSON format for cross-deployment sync.

SECURITY NOTES:
- Emails are exported DECRYPTED for portability across encryption keys
- Passwords are exported as HASHED values (never plaintext)
- Users can log in after import if bcrypt versions match, OR
- Use --set-password on import to assign new passwords

Usage:
    python3 export_users.py --output users.json
    python3 export_users.py --output users.json --role admin
    python3 export_users.py --output users.json --include-inactive

Output Format:
{
    "metadata": {
        "exported_at": "2024-01-15T10:30:00Z",
        "source_key_fingerprint": "abc123...",
        "version": "1.0",
        "total_users": 5
    },
    "users": [
        {
            "email": "user@example.com",
            "role": "artist",
            "is_active": true,
            "created_at": "2024-01-01T00:00:00Z",
            "hashed_password": "$2b$12$...",
            "artist_link": {
                "artist_id": "ARTS0001",
                "artist_name": "John Doe"
            }
        }
    ]
}
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from hashlib import sha256

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402
load_dotenv()

from app import app, db, User  # noqa: E402
from create_tbls import init_tables  # noqa: E402


def get_key_fingerprint():
    """Get a fingerprint of the current encryption key (for verification).

    Returns first 8 characters of SHA256 hash of the key.
    """
    key_env = os.getenv("PII_ENCRYPTION_KEY") or os.getenv("SECRET_KEY") or ""
    if not key_env:
        return "ephemeral"
    return sha256(key_env.encode()).hexdigest()[:8]


def export_users(output_file, role_filter=None, include_inactive=False):
    """Export users to JSON file.

    Args:
        output_file: Path to output JSON file
        role_filter: Optional role to filter by (admin, artist, guest)
        include_inactive: Whether to include inactive/deleted users
    """
    with app.app_context():
        Artist, _, _, _, _, _, _ = init_tables(db)

        query = User.query

        if role_filter:
            query = query.filter(User.role == role_filter)

        if not include_inactive:
            query = query.filter(User.is_active == True)  # noqa: E712

        users = query.all()

        export_data = {
            "metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "source_key_fingerprint": get_key_fingerprint(),
                "version": "1.0",
                "total_users": len(users)
            },
            "users": []
        }

        for user in users:
            user_data = {
                "email": user.email,  # Already decrypted by EncryptedString
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "hashed_password": user.hashed_password,
                "artist_link": None
            }

            # Check for linked artist
            linked_artist = Artist.query.filter_by(user_id=user.id, is_deleted=False).first()
            if linked_artist:
                user_data["artist_link"] = {
                    "artist_id": linked_artist.artist_id,
                    "artist_name": f"{linked_artist.artist_fname} {linked_artist.artist_lname}"
                }

            export_data["users"].append(user_data)

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"Exported {len(users)} users to {output_file}")
        print(f"Key fingerprint: {get_key_fingerprint()}")
        if role_filter:
            print(f"Filtered by role: {role_filter}")
        if include_inactive:
            print("Included inactive users")


def main():
    parser = argparse.ArgumentParser(
        description="Export users to JSON for cross-deployment sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output JSON file path"
    )
    parser.add_argument(
        "--role",
        choices=["admin", "artist", "guest"],
        help="Filter by role"
    )
    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include inactive/deleted users"
    )

    args = parser.parse_args()
    export_users(args.output, args.role, args.include_inactive)


if __name__ == "__main__":
    main()
