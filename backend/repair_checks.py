#!/usr/bin/env python3
"""
Canvas & Clay Repair Checks

Database-level integrity scanning for the repair wizard.
Detects and fixes:
- Orphaned files (files on disk not referenced in database)
- Missing files (database records pointing to non-existent files)
- Missing thumbnails (originals exist but thumbnails missing)

Usage:
    python3 repair_checks.py --scan           # Scan for issues
    python3 repair_checks.py --fix            # Fix all issues
    python3 repair_checks.py --fix-orphans    # Fix only orphaned files
    python3 repair_checks.py --fix-missing    # Fix only missing file records
    python3 repair_checks.py --fix-thumbnails # Regenerate missing thumbnails
"""

import argparse
import json
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ARTWORKS_DIR = os.path.join(UPLOADS_DIR, 'artworks')
THUMBNAILS_DIR = os.path.join(UPLOADS_DIR, 'thumbnails')


def get_app_context():
    """Initialize Flask app and return context with models."""
    from app import app, db
    from create_tbls import init_tables

    ArtworkPhoto = init_tables(db)[6]  # ArtworkPhoto is index 6 in tuple
    return app, db, ArtworkPhoto


def scan_orphaned_files():
    """
    Find files on disk that are not referenced in the database.

    Returns:
        dict: {
            'artworks': [list of orphaned artwork files],
            'thumbnails': [list of orphaned thumbnail files],
            'count': total count
        }
    """
    app, db, ArtworkPhoto = get_app_context()

    orphaned = {
        'artworks': [],
        'thumbnails': [],
        'count': 0
    }

    with app.app_context():
        # Get all photo records from database
        photos = ArtworkPhoto.query.all()
        db_artwork_files = set()
        db_thumbnail_files = set()

        for photo in photos:
            if photo.file_path:
                db_artwork_files.add(os.path.basename(photo.file_path))
            if photo.thumbnail_path:
                db_thumbnail_files.add(os.path.basename(photo.thumbnail_path))

        # Scan artworks directory
        if os.path.exists(ARTWORKS_DIR):
            for filename in os.listdir(ARTWORKS_DIR):
                filepath = os.path.join(ARTWORKS_DIR, filename)
                if os.path.isfile(filepath) and filename not in db_artwork_files:
                    orphaned['artworks'].append({
                        'filename': filename,
                        'path': filepath,
                        'size': os.path.getsize(filepath)
                    })

        # Scan thumbnails directory
        if os.path.exists(THUMBNAILS_DIR):
            for filename in os.listdir(THUMBNAILS_DIR):
                filepath = os.path.join(THUMBNAILS_DIR, filename)
                if os.path.isfile(filepath) and filename not in db_thumbnail_files:
                    orphaned['thumbnails'].append({
                        'filename': filename,
                        'path': filepath,
                        'size': os.path.getsize(filepath)
                    })

        orphaned['count'] = len(orphaned['artworks']) + len(orphaned['thumbnails'])

    return orphaned


def scan_missing_files():
    """
    Find database records pointing to files that don't exist on disk.

    Returns:
        dict: {
            'photos': [list of photo records with missing files],
            'count': total count
        }
    """
    app, db, ArtworkPhoto = get_app_context()

    missing = {
        'photos': [],
        'count': 0
    }

    with app.app_context():
        photos = ArtworkPhoto.query.all()

        for photo in photos:
            issues = []
            artwork_path = os.path.join(UPLOADS_DIR, photo.file_path) if photo.file_path else None
            thumb_path = os.path.join(UPLOADS_DIR, photo.thumbnail_path) if photo.thumbnail_path else None

            if artwork_path and not os.path.exists(artwork_path):
                issues.append('artwork_missing')
            if thumb_path and not os.path.exists(thumb_path):
                issues.append('thumbnail_missing')

            if issues:
                missing['photos'].append({
                    'photo_id': photo.photo_id,
                    'filename': photo.filename,
                    'artwork_num': photo.artwork_num,
                    'file_path': photo.file_path,
                    'thumbnail_path': photo.thumbnail_path,
                    'issues': issues
                })

        missing['count'] = len(missing['photos'])

    return missing


def scan_missing_thumbnails():
    """
    Find photos where original exists but thumbnail is missing.

    Returns:
        dict: {
            'photos': [list of photos needing thumbnail regeneration],
            'count': total count
        }
    """
    app, db, ArtworkPhoto = get_app_context()

    missing_thumbs = {
        'photos': [],
        'count': 0
    }

    with app.app_context():
        photos = ArtworkPhoto.query.all()

        for photo in photos:
            artwork_path = os.path.join(UPLOADS_DIR, photo.file_path) if photo.file_path else None
            thumb_path = os.path.join(UPLOADS_DIR, photo.thumbnail_path) if photo.thumbnail_path else None

            # Original exists but thumbnail doesn't
            if artwork_path and os.path.exists(artwork_path):
                if not thumb_path or not os.path.exists(thumb_path):
                    missing_thumbs['photos'].append({
                        'photo_id': photo.photo_id,
                        'filename': photo.filename,
                        'file_path': photo.file_path,
                        'thumbnail_path': photo.thumbnail_path
                    })

        missing_thumbs['count'] = len(missing_thumbs['photos'])

    return missing_thumbs


def fix_orphaned_files(dry_run=False):
    """
    Remove orphaned files from disk.

    Args:
        dry_run: If True, only report what would be deleted

    Returns:
        dict: Results of the fix operation
    """
    orphaned = scan_orphaned_files()
    results = {
        'deleted_artworks': [],
        'deleted_thumbnails': [],
        'bytes_freed': 0,
        'dry_run': dry_run
    }

    for item in orphaned['artworks']:
        if dry_run:
            results['deleted_artworks'].append(item['filename'])
            results['bytes_freed'] += item['size']
        else:
            try:
                os.remove(item['path'])
                results['deleted_artworks'].append(item['filename'])
                results['bytes_freed'] += item['size']
            except OSError as e:
                print(f"Error deleting {item['path']}: {e}", file=sys.stderr)

    for item in orphaned['thumbnails']:
        if dry_run:
            results['deleted_thumbnails'].append(item['filename'])
            results['bytes_freed'] += item['size']
        else:
            try:
                os.remove(item['path'])
                results['deleted_thumbnails'].append(item['filename'])
                results['bytes_freed'] += item['size']
            except OSError as e:
                print(f"Error deleting {item['path']}: {e}", file=sys.stderr)

    return results


def fix_missing_files(dry_run=False):
    """
    Remove database records for files that don't exist on disk.

    Args:
        dry_run: If True, only report what would be deleted

    Returns:
        dict: Results of the fix operation
    """
    app, db, ArtworkPhoto = get_app_context()
    missing = scan_missing_files()
    results = {
        'deleted_records': [],
        'dry_run': dry_run
    }

    with app.app_context():
        for item in missing['photos']:
            # Only delete if artwork file is missing (not just thumbnail)
            if 'artwork_missing' in item['issues']:
                if dry_run:
                    results['deleted_records'].append(item['photo_id'])
                else:
                    try:
                        photo = ArtworkPhoto.query.get(item['photo_id'])
                        if photo:
                            db.session.delete(photo)
                            results['deleted_records'].append(item['photo_id'])
                    except Exception as e:
                        print(f"Error deleting record {item['photo_id']}: {e}", file=sys.stderr)

        if not dry_run:
            db.session.commit()

    return results


def fix_missing_thumbnails(dry_run=False):
    """
    Regenerate missing thumbnails from original images.

    Args:
        dry_run: If True, only report what would be regenerated

    Returns:
        dict: Results of the fix operation
    """
    app, db, ArtworkPhoto = get_app_context()
    missing = scan_missing_thumbnails()
    results = {
        'regenerated': [],
        'failed': [],
        'dry_run': dry_run
    }

    if dry_run:
        results['regenerated'] = [p['photo_id'] for p in missing['photos']]
        return results

    # Import Pillow for thumbnail generation
    try:
        from PIL import Image
    except ImportError:
        print("Error: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
        return results

    THUMBNAIL_SIZE = (200, 200)

    with app.app_context():
        for item in missing['photos']:
            artwork_path = os.path.join(UPLOADS_DIR, item['file_path'])

            # Determine thumbnail path
            if item['thumbnail_path']:
                thumb_path = os.path.join(UPLOADS_DIR, item['thumbnail_path'])
            else:
                # Generate thumbnail path
                base_name = os.path.splitext(os.path.basename(item['file_path']))[0]
                thumb_filename = f"thumb_{base_name}.jpg"
                thumb_path = os.path.join(THUMBNAILS_DIR, thumb_filename)

            try:
                # Create thumbnails directory if needed
                os.makedirs(os.path.dirname(thumb_path), exist_ok=True)

                # Generate thumbnail
                with Image.open(artwork_path) as img:
                    # Convert to RGB if necessary (for PNG with transparency)
                    if img.mode in ('RGBA', 'P'):
                        img = img.convert('RGB')

                    # Create thumbnail maintaining aspect ratio
                    img.thumbnail(THUMBNAIL_SIZE, Image.Resampling.LANCZOS)
                    img.save(thumb_path, 'JPEG', quality=85, optimize=True)

                # Update database record if thumbnail_path was empty
                photo = ArtworkPhoto.query.get(item['photo_id'])
                if photo and not photo.thumbnail_path:
                    photo.thumbnail_path = os.path.relpath(thumb_path, UPLOADS_DIR)

                results['regenerated'].append(item['photo_id'])

            except Exception as e:
                print(f"Error regenerating thumbnail for {item['photo_id']}: {e}", file=sys.stderr)
                results['failed'].append({
                    'photo_id': item['photo_id'],
                    'error': str(e)
                })

        db.session.commit()

    return results


def run_full_scan():
    """
    Run all scans and return comprehensive results.

    Returns:
        dict: Combined results from all scans
    """
    return {
        'orphaned_files': scan_orphaned_files(),
        'missing_files': scan_missing_files(),
        'missing_thumbnails': scan_missing_thumbnails(),
        'timestamp': datetime.now().isoformat()
    }


def run_all_fixes(dry_run=False):
    """
    Run all fixes and return comprehensive results.

    Args:
        dry_run: If True, only report what would be fixed

    Returns:
        dict: Combined results from all fixes
    """
    return {
        'orphaned_files': fix_orphaned_files(dry_run),
        'missing_files': fix_missing_files(dry_run),
        'missing_thumbnails': fix_missing_thumbnails(dry_run),
        'timestamp': datetime.now().isoformat()
    }


def format_bytes(size):
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def print_scan_results(results):
    """Print scan results in human-readable format."""
    orphaned = results['orphaned_files']
    missing = results['missing_files']
    thumbs = results['missing_thumbnails']

    print("\nData Integrity Scan Results")
    print("=" * 40)

    # Orphaned files
    print(f"\nOrphaned Files: {orphaned['count']}")
    if orphaned['artworks']:
        print(f"  Artwork files: {len(orphaned['artworks'])}")
        for item in orphaned['artworks'][:5]:
            print(f"    - {item['filename']} ({format_bytes(item['size'])})")
        if len(orphaned['artworks']) > 5:
            print(f"    ... and {len(orphaned['artworks']) - 5} more")
    if orphaned['thumbnails']:
        print(f"  Thumbnail files: {len(orphaned['thumbnails'])}")

    # Missing files
    print(f"\nMissing Files: {missing['count']}")
    if missing['photos']:
        for item in missing['photos'][:5]:
            print(f"  - Photo {item['photo_id']}: {', '.join(item['issues'])}")
        if len(missing['photos']) > 5:
            print(f"  ... and {len(missing['photos']) - 5} more")

    # Missing thumbnails
    print(f"\nMissing Thumbnails: {thumbs['count']}")
    if thumbs['photos']:
        for item in thumbs['photos'][:5]:
            print(f"  - Photo {item['photo_id']}: {item['filename']}")
        if len(thumbs['photos']) > 5:
            print(f"  ... and {len(thumbs['photos']) - 5} more")

    # Summary
    total_issues = orphaned['count'] + missing['count'] + thumbs['count']
    print(f"\n{'=' * 40}")
    if total_issues == 0:
        print("No issues found.")
    else:
        print(f"Total issues: {total_issues}")
        print("\nRun with --fix to repair all issues")


def print_fix_results(results):
    """Print fix results in human-readable format."""
    print("\nRepair Results")
    print("=" * 40)

    orphaned = results['orphaned_files']
    missing = results['missing_files']
    thumbs = results['missing_thumbnails']

    prefix = "[DRY RUN] " if orphaned.get('dry_run') else ""

    # Orphaned files
    deleted_count = len(orphaned['deleted_artworks']) + len(orphaned['deleted_thumbnails'])
    if deleted_count:
        print(f"\n{prefix}Deleted orphaned files: {deleted_count}")
        print(f"  Space freed: {format_bytes(orphaned['bytes_freed'])}")

    # Missing file records
    if missing['deleted_records']:
        print(f"\n{prefix}Removed missing file records: {len(missing['deleted_records'])}")

    # Thumbnails
    if thumbs['regenerated']:
        print(f"\n{prefix}Regenerated thumbnails: {len(thumbs['regenerated'])}")
    if thumbs.get('failed'):
        print(f"  Failed: {len(thumbs['failed'])}")

    print(f"\n{'=' * 40}")
    if orphaned.get('dry_run'):
        print("This was a dry run. Use --fix without --dry-run to apply changes.")
    else:
        print("Repairs complete.")


def main():
    parser = argparse.ArgumentParser(
        description='Canvas & Clay data integrity repair tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--scan', action='store_true',
                        help='Scan for issues (default action)')
    parser.add_argument('--fix', action='store_true',
                        help='Fix all issues')
    parser.add_argument('--fix-orphans', action='store_true',
                        help='Remove orphaned files only')
    parser.add_argument('--fix-missing', action='store_true',
                        help='Remove missing file records only')
    parser.add_argument('--fix-thumbnails', action='store_true',
                        help='Regenerate missing thumbnails only')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without making changes')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON')

    args = parser.parse_args()

    # Default to scan if no action specified
    if not any([args.scan, args.fix, args.fix_orphans, args.fix_missing, args.fix_thumbnails]):
        args.scan = True

    try:
        if args.scan:
            results = run_full_scan()
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_scan_results(results)

        elif args.fix:
            results = run_all_fixes(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_fix_results(results)

        elif args.fix_orphans:
            results = fix_orphaned_files(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"{'[DRY RUN] ' if args.dry_run else ''}Deleted {len(results['deleted_artworks']) + len(results['deleted_thumbnails'])} orphaned files")
                print(f"Space freed: {format_bytes(results['bytes_freed'])}")

        elif args.fix_missing:
            results = fix_missing_files(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"{'[DRY RUN] ' if args.dry_run else ''}Removed {len(results['deleted_records'])} missing file records")

        elif args.fix_thumbnails:
            results = fix_missing_thumbnails(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"{'[DRY RUN] ' if args.dry_run else ''}Regenerated {len(results['regenerated'])} thumbnails")
                if results.get('failed'):
                    print(f"Failed: {len(results['failed'])}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
