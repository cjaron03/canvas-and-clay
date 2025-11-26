#!/usr/bin/env python3
"""
Cleanup utility for orphaned artwork photos.

This script identifies and deletes ArtworkPhoto database records that point to
files which no longer exist on disk. This situation can occur when:
- Container was rebuilt before persistent volume was added
- Files were manually deleted but database records remain
- Upload process failed partway through

Usage:
    python cleanup_orphaned_photos.py          # Dry run (shows what would be deleted)
    python cleanup_orphaned_photos.py --delete # Actually delete orphaned records
"""

import os
import argparse
from app import app, db
from create_tbls import init_tables


def find_orphaned_photos():
    """Find all ArtworkPhoto records with missing files.

    Returns:
        list: ArtworkPhoto objects with missing files
    """
    ArtworkPhoto = init_tables(db)[6]

    orphaned = []
    total_checked = 0

    for photo in ArtworkPhoto.query.all():
        total_checked += 1

        # Check if both the full-size image and thumbnail exist
        file_path = os.path.join('/app', photo.file_path)
        thumb_path = os.path.join('/app', photo.thumbnail_path)

        file_exists = os.path.exists(file_path)
        thumb_exists = os.path.exists(thumb_path)

        if not file_exists or not thumb_exists:
            orphaned.append({
                'photo': photo,
                'file_missing': not file_exists,
                'thumb_missing': not thumb_exists
            })

    return orphaned, total_checked


def display_orphaned_summary(orphaned_list):
    """Display summary of orphaned photos.

    Args:
        orphaned_list (list): List of orphaned photo dictionaries
    """
    if not orphaned_list:
        print("\n✅ No orphaned photos found! All database records have corresponding files.")
        return

    print(f"\n⚠️  Found {len(orphaned_list)} orphaned photo(s):\n")
    print("-" * 100)

    for item in orphaned_list:
        photo = item['photo']
        print(f"Photo ID:       {photo.photo_id}")
        print(f"Artwork:        {photo.artwork_num}")
        print(f"Filename:       {photo.filename}")
        print(f"File Path:      {photo.file_path} {'[MISSING]' if item['file_missing'] else '[EXISTS]'}")
        print(f"Thumbnail Path: {photo.thumbnail_path} {'[MISSING]' if item['thumb_missing'] else '[EXISTS]'}")
        print(f"Uploaded At:    {photo.uploaded_at}")
        print(f"Uploaded By:    User ID {photo.uploaded_by}")
        print("-" * 100)


def delete_orphaned_photos(orphaned_list):
    """Delete orphaned photo records from database.

    Args:
        orphaned_list (list): List of orphaned photo dictionaries

    Returns:
        int: Number of records deleted
    """
    deleted_count = 0

    for item in orphaned_list:
        photo = item['photo']
        db.session.delete(photo)
        deleted_count += 1
        print(f"✓ Deleted photo record {photo.photo_id} ({photo.filename})")

    db.session.commit()
    return deleted_count


def main():
    parser = argparse.ArgumentParser(
        description='Clean up orphaned artwork photo database records',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (show what would be deleted)
  python cleanup_orphaned_photos.py

  # Actually delete orphaned records
  python cleanup_orphaned_photos.py --delete

  # Run inside Docker container
  docker exec canvas_backend python cleanup_orphaned_photos.py --delete
        """
    )

    parser.add_argument(
        '--delete',
        action='store_true',
        help='Actually delete orphaned records (default is dry run)'
    )

    args = parser.parse_args()

    print("=" * 100)
    print("ORPHANED PHOTO CLEANUP UTILITY")
    print("=" * 100)

    with app.app_context():
        # Find orphaned photos
        print("\nScanning database for orphaned photo records...")
        orphaned_list, total_checked = find_orphaned_photos()
        print(f"✓ Checked {total_checked} photo records")

        # Display summary
        display_orphaned_summary(orphaned_list)

        if not orphaned_list:
            return

        # Delete if requested
        if args.delete:
            print(f"\n⚠️  DELETING {len(orphaned_list)} orphaned photo record(s)...\n")
            deleted_count = delete_orphaned_photos(orphaned_list)
            print(f"\n✅ Successfully deleted {deleted_count} orphaned photo record(s)")
            print("\nNote: The artworks still exist, but their photo associations have been removed.")
            print("You can now re-upload photos for these artworks.")
        else:
            print("\n💡 DRY RUN MODE - No records were deleted.")
            print(f"   To actually delete these {len(orphaned_list)} record(s), run with --delete flag:")
            print("   python cleanup_orphaned_photos.py --delete")

    print("\n" + "=" * 100)


if __name__ == '__main__':
    main()
