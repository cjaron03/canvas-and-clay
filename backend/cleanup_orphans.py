#!/usr/bin/env python3
"""Cleanup orphaned photo database records.

This script identifies and removes ArtworkPhoto records that reference files
which no longer exist on disk. This can happen due to:
- Docker volume mount precedence issues
- Demo data seeding with placeholder records
- Manual file deletions

Run this script on startup to maintain database integrity.
"""
import os
import sys


def cleanup_orphan_photos():
    """Remove ArtworkPhoto records where the actual file doesn't exist.

    Returns:
        tuple: (total_checked, orphans_removed, errors)
    """
    # Import inside function to avoid circular imports
    from app import app, db
    from create_tbls import init_tables
    from upload_utils import ARTWORKS_DIR, THUMBNAILS_DIR

    ArtworkPhoto = init_tables(db)[6]  # Position 6 in the tuple

    total_checked = 0
    orphans_removed = 0
    errors = []

    with app.app_context():
        photos = ArtworkPhoto.query.all()
        total_checked = len(photos)

        for photo in photos:
            # Check if the main file exists
            photo_path = os.path.join(ARTWORKS_DIR, photo.filename)
            if not os.path.exists(photo_path):
                try:
                    # Also check for thumbnail
                    thumb_path = os.path.join(THUMBNAILS_DIR, f"thumb_{photo.filename}")

                    # Log what we're removing
                    print(f"  Removing orphan: {photo.photo_id} ({photo.filename})")

                    db.session.delete(photo)
                    orphans_removed += 1

                    # Clean up thumbnail if it exists
                    if os.path.exists(thumb_path):
                        os.remove(thumb_path)
                        print(f"    Removed stale thumbnail: thumb_{photo.filename}")

                except Exception as e:
                    errors.append(f"Error removing {photo.photo_id}: {e}")

        if orphans_removed > 0:
            db.session.commit()

    return total_checked, orphans_removed, errors


def main():
    """Main entry point for orphan cleanup."""
    print("Checking for orphaned photo records...")

    try:
        total, removed, errors = cleanup_orphan_photos()

        if removed > 0:
            print(f"✓ Cleaned up {removed} orphaned photo record(s) (checked {total} total)")
        else:
            print(f"✓ No orphaned records found ({total} photos verified)")

        for error in errors:
            print(f"  Warning: {error}", file=sys.stderr)

        return 0 if not errors else 1

    except Exception as e:
        print(f"Error during orphan cleanup: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
