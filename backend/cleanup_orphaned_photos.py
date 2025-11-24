#!/usr/bin/env python3
"""Cleanup script to remove orphaned photo records from the database.

This script finds ArtworkPhoto records where the referenced files don't exist
on disk and removes those records to keep the database clean.

Usage:
    # Run inside docker container (recommended):
    docker compose exec backend python cleanup_orphaned_photos.py [--dry-run] [--verbose]
    
    # Or run locally (requires database access):
    python cleanup_orphaned_photos.py [--dry-run] [--verbose]

Options:
    --dry-run    Show what would be deleted without actually deleting
    --verbose    Show detailed information about each orphaned record

Note:
    When running locally, ensure DATABASE_URL in .env is configured correctly
    to access the database (e.g., postgresql://user:pass@localhost:5432/dbname)
"""

import os
import sys

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, ArtworkPhoto  # noqa: E402


def check_file_exists(file_path):
    """Check if a file exists, handling both relative and absolute paths."""
    if not file_path:
        return False
    
    # Get backend directory
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    
    # If path starts with 'uploads/', it's relative to backend directory
    if file_path.startswith('uploads/'):
        full_path = os.path.join(backend_dir, file_path)
    else:
        # Assume it's relative to backend/uploads directory
        uploads_dir = os.path.join(backend_dir, 'uploads')
        full_path = os.path.join(uploads_dir, file_path)
    
    return os.path.exists(full_path)


def cleanup_orphaned_photos(dry_run=False, verbose=False):
    """Find and remove orphaned photo records.
    
    Args:
        dry_run: If True, only report what would be deleted without deleting
        verbose: If True, show detailed information about each orphaned record
    """
    print("scanning for orphaned photo records...")
    print("-" * 60)
    
    try:
        # Get all photos - need to do this within app context
        with app.app_context():
            all_photos = ArtworkPhoto.query.all()
            total_photos = len(all_photos)
            
            orphaned_photos = []
            
            for photo in all_photos:
                # Check if both files exist
                file_exists = check_file_exists(photo.file_path)
                thumbnail_exists = check_file_exists(photo.thumbnail_path)
                
                if not file_exists or not thumbnail_exists:
                    # Store photo_id instead of photo object to avoid session issues
                    orphaned_photos.append({
                        'photo_id': photo.photo_id,
                        'artwork_num': photo.artwork_num,
                        'filename': photo.filename,
                        'file_path': photo.file_path,
                        'thumbnail_path': photo.thumbnail_path,
                        'uploaded_at': photo.uploaded_at,
                        'file_exists': file_exists,
                        'thumbnail_exists': thumbnail_exists
                    })
    except Exception as e:
        print(f"error connecting to database: {e}")
        print("\nnote: if running locally, make sure:")
        print("  1. database is running (docker compose up db)")
        print("  2. DATABASE_URL in .env points to correct database")
        print("  3. or run this script inside docker container")
        sys.exit(1)
    
    orphaned_count = len(orphaned_photos)
    
    print(f"total photos in database: {total_photos}")
    print(f"orphaned photos found: {orphaned_count}")
    print("-" * 60)
    
    if orphaned_count == 0:
        print("no orphaned photos found. database is clean!")
        return
    
    if verbose or dry_run:
        print("\norphaned photo details:")
        print("-" * 60)
        for i, orphan in enumerate(orphaned_photos, 1):
            print(f"\n{i}. photo_id: {orphan['photo_id']}")
            print(f"   artwork_num: {orphan['artwork_num'] or 'None (orphaned)'}")
            print(f"   filename: {orphan['filename']}")
            print(f"   file_path: {orphan['file_path']}")
            print(f"   thumbnail_path: {orphan['thumbnail_path']}")
            print(f"   file exists: {orphan['file_exists']}")
            print(f"   thumbnail exists: {orphan['thumbnail_exists']}")
            print(f"   uploaded_at: {orphan['uploaded_at']}")
    
    if dry_run:
        print("\n" + "=" * 60)
        print(f"dry-run mode: would delete {orphaned_count} orphaned photo record(s)")
        print("=" * 60)
        print("\nto actually delete these records, run without --dry-run flag")
        return
    
    # Confirm deletion
    print(f"\nabout to delete {orphaned_count} orphaned photo record(s)")
    response = input("continue? (yes/no): ").strip().lower()
    
    if response != 'yes':
        print("cleanup cancelled.")
        return
    
    # Delete orphaned photos - query fresh in new session
    print("\ndeleting orphaned photos...")
    deleted_count = 0
    
    try:
        with app.app_context():
            for orphan in orphaned_photos:
                # Query fresh photo object in this session
                photo = ArtworkPhoto.query.get(orphan['photo_id'])
                if photo:
                    photo_id = photo.photo_id
                    artwork_num = photo.artwork_num
                    
                    db.session.delete(photo)
                    deleted_count += 1
                    
                    if verbose:
                        print(f"  deleted photo {photo_id} (artwork: {artwork_num or 'None'})")
            
            db.session.commit()
            print(f"\nsuccessfully deleted {deleted_count} orphaned photo record(s)")
            
    except Exception as e:
        db.session.rollback()
        print(f"\nerror during cleanup: {e}")
        print("changes have been rolled back")
        sys.exit(1)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Clean up orphaned photo records from the database'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='show what would be deleted without actually deleting'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='show detailed information about each orphaned record'
    )
    
    args = parser.parse_args()
    
    with app.app_context():
        cleanup_orphaned_photos(dry_run=args.dry_run, verbose=args.verbose)


if __name__ == '__main__':
    main()

