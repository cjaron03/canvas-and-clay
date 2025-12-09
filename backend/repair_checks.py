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
import fcntl
import json
import os
import sys
from contextlib import contextmanager, redirect_stdout
from datetime import datetime
from io import StringIO

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Base directory for the app (file_path in DB already includes 'uploads/' prefix)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
ARTWORKS_DIR = os.path.join(UPLOADS_DIR, 'artworks')
THUMBNAILS_DIR = os.path.join(UPLOADS_DIR, 'thumbnails')

# Lock file to prevent concurrent repair operations (TOCTOU race condition protection)
REPAIR_LOCK_FILE = '/tmp/canvas-clay-repair.lock'

# Global flag to suppress app import output (set by --json flag)
_suppress_output = False


class RepairLockError(Exception):
    """Raised when repair lock cannot be acquired."""
    pass


@contextmanager
def repair_lock(blocking=True, timeout=None):
    """
    Context manager for exclusive repair operation lock.

    Prevents race conditions where concurrent repair operations could
    delete legitimate files due to TOCTOU between DB query and disk scan.

    Args:
        blocking: If True, wait for lock. If False, fail immediately if locked.
        timeout: Max seconds to wait (None = wait forever). Only used if blocking=True.

    Raises:
        RepairLockError: If lock cannot be acquired (non-blocking or timeout)

    Usage:
        with repair_lock():
            # Critical repair operations here
            pass
    """
    lock_fd = None
    try:
        # Create lock file if it doesn't exist
        lock_fd = open(REPAIR_LOCK_FILE, 'w')

        if blocking:
            if timeout is not None:
                # Use non-blocking with retry for timeout behavior
                import time
                start = time.time()
                while True:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.time() - start >= timeout:
                            raise RepairLockError(
                                f"Could not acquire repair lock within {timeout}s. "
                                "Another repair operation may be running."
                            )
                        time.sleep(0.1)
            else:
                # Wait indefinitely
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
        else:
            # Non-blocking - fail immediately if locked
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RepairLockError(
                    "Repair operation already in progress. "
                    "Please wait for it to complete or check for stale lock."
                )

        # Write PID to lock file for debugging
        lock_fd.write(f"{os.getpid()}\n")
        lock_fd.flush()

        yield

    finally:
        if lock_fd:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
            except Exception:
                pass


def get_app_context():
    """Initialize Flask app and return context with models."""
    global _suppress_output
    if _suppress_output:
        # Suppress Flask startup messages for JSON output
        with redirect_stdout(StringIO()):
            from app import app, db
    else:
        from app import app, db
    from create_tbls import init_tables

    ArtworkPhoto = init_tables(db)[6]  # ArtworkPhoto is index 6 in tuple
    return app, db, ArtworkPhoto


def scan_orphaned_files():
    """
    Find files on disk that are not referenced in the database.

    SAFETY: Will NOT report files as orphaned if:
    - Database query fails
    - Database returns zero photos (likely a bug, not legitimate empty state)
    - More than 50% of files would be marked orphaned (suspicious)

    Returns:
        dict: {
            'artworks': [list of orphaned artwork files],
            'thumbnails': [list of orphaned thumbnail files],
            'count': total count,
            'skipped': bool - True if scan was skipped due to safety checks
            'skip_reason': str - Reason for skipping (if applicable)
        }
    """
    app, db, ArtworkPhoto = get_app_context()

    orphaned = {
        'artworks': [],
        'thumbnails': [],
        'count': 0,
        'skipped': False,
        'skip_reason': None
    }

    with app.app_context():
        # Get all photo records from database
        try:
            photos = ArtworkPhoto.query.all()
        except Exception as e:
            orphaned['skipped'] = True
            orphaned['skip_reason'] = f'Database query failed: {str(e)[:50]}'
            return orphaned

        db_artwork_files = set()
        db_thumbnail_files = set()

        for photo in photos:
            if photo.file_path:
                db_artwork_files.add(os.path.basename(photo.file_path))
            if photo.thumbnail_path:
                db_thumbnail_files.add(os.path.basename(photo.thumbnail_path))

        # SAFETY CHECK: If database has no photos but files exist, don't delete anything
        files_on_disk = 0
        if os.path.exists(ARTWORKS_DIR):
            files_on_disk += len([f for f in os.listdir(ARTWORKS_DIR) if os.path.isfile(os.path.join(ARTWORKS_DIR, f))])

        if len(db_artwork_files) == 0 and files_on_disk > 0:
            orphaned['skipped'] = True
            orphaned['skip_reason'] = (
                f'Database has 0 photos but {files_on_disk} files exist - refusing to mark all as orphaned'
            )
            return orphaned

        # Scan artworks directory
        potential_orphans = []
        if os.path.exists(ARTWORKS_DIR):
            for filename in os.listdir(ARTWORKS_DIR):
                filepath = os.path.join(ARTWORKS_DIR, filename)
                if os.path.isfile(filepath) and filename not in db_artwork_files:
                    potential_orphans.append({
                        'filename': filename,
                        'path': filepath,
                        'size': os.path.getsize(filepath)
                    })

        # SAFETY CHECK: If more than 50% of files would be orphaned, something is wrong
        if files_on_disk > 0 and len(potential_orphans) > (files_on_disk * 0.5):
            orphaned['skipped'] = True
            orphaned['skip_reason'] = (
                f'{len(potential_orphans)}/{files_on_disk} files would be orphaned (>50%) - skipping'
            )
            return orphaned

        orphaned['artworks'] = potential_orphans

        # Scan thumbnails directory (same logic)
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
            # file_path already includes 'uploads/' prefix, so join with BASE_DIR
            artwork_path = os.path.join(BASE_DIR, photo.file_path) if photo.file_path else None
            thumb_path = os.path.join(BASE_DIR, photo.thumbnail_path) if photo.thumbnail_path else None

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
            # file_path already includes 'uploads/' prefix, so join with BASE_DIR
            artwork_path = os.path.join(BASE_DIR, photo.file_path) if photo.file_path else None
            thumb_path = os.path.join(BASE_DIR, photo.thumbnail_path) if photo.thumbnail_path else None

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
        'dry_run': dry_run,
        'skipped': False,
        'skip_reason': None
    }

    # SAFETY: If scan was skipped due to safety checks, don't delete anything
    if orphaned.get('skipped'):
        results['skipped'] = True
        results['skip_reason'] = orphaned.get('skip_reason', 'Scan was skipped')
        print(f"SAFETY: Refusing to delete files - {results['skip_reason']}", file=sys.stderr)
        return results

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
            # file_path already includes 'uploads/' prefix, so join with BASE_DIR
            artwork_path = os.path.join(BASE_DIR, item['file_path'])

            # Determine thumbnail path
            if item['thumbnail_path']:
                thumb_path = os.path.join(BASE_DIR, item['thumbnail_path'])
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
                    # DB stores paths with 'uploads/' prefix, so relpath from BASE_DIR
                    photo.thumbnail_path = os.path.relpath(thumb_path, BASE_DIR)

                results['regenerated'].append(item['photo_id'])

            except Exception as e:
                print(f"Error regenerating thumbnail for {item['photo_id']}: {e}", file=sys.stderr)
                results['failed'].append({
                    'photo_id': item['photo_id'],
                    'error': str(e)
                })

        db.session.commit()

    return results


def run_full_scan(use_lock=True):
    """
    Run all scans and return comprehensive results.

    Args:
        use_lock: If True, acquire exclusive lock to prevent race conditions

    Returns:
        dict: Combined results from all scans
    """
    def _do_scan():
        return {
            'orphaned_files': scan_orphaned_files(),
            'missing_files': scan_missing_files(),
            'missing_thumbnails': scan_missing_thumbnails(),
            'timestamp': datetime.now().isoformat()
        }

    if use_lock:
        with repair_lock(blocking=False):
            return _do_scan()
    else:
        return _do_scan()


def run_all_fixes(dry_run=False, use_lock=True):
    """
    Run all fixes and return comprehensive results.

    Args:
        dry_run: If True, only report what would be fixed
        use_lock: If True, acquire exclusive lock to prevent race conditions

    Returns:
        dict: Combined results from all fixes
    """
    def _do_fixes():
        return {
            'orphaned_files': fix_orphaned_files(dry_run),
            'missing_files': fix_missing_files(dry_run),
            'missing_thumbnails': fix_missing_thumbnails(dry_run),
            'timestamp': datetime.now().isoformat()
        }

    if use_lock:
        with repair_lock(blocking=False):
            return _do_fixes()
    else:
        return _do_fixes()


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
    parser.add_argument('--no-lock', action='store_true',
                        help='Skip exclusive lock (dangerous, for testing only)')

    args = parser.parse_args()

    # Suppress Flask startup output when JSON mode is enabled
    global _suppress_output
    if args.json:
        _suppress_output = True

    # Default to scan if no action specified
    if not any([args.scan, args.fix, args.fix_orphans, args.fix_missing, args.fix_thumbnails]):
        args.scan = True

    use_lock = not args.no_lock

    try:
        if args.scan:
            results = run_full_scan(use_lock=use_lock)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_scan_results(results)

        elif args.fix:
            results = run_all_fixes(args.dry_run, use_lock=use_lock)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_fix_results(results)

        elif args.fix_orphans:
            if use_lock:
                with repair_lock(blocking=False):
                    results = fix_orphaned_files(args.dry_run)
            else:
                results = fix_orphaned_files(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                prefix = '[DRY RUN] ' if args.dry_run else ''
                deleted = len(results['deleted_artworks']) + len(results['deleted_thumbnails'])
                print(f"{prefix}Deleted {deleted} orphaned files")
                print(f"Space freed: {format_bytes(results['bytes_freed'])}")

        elif args.fix_missing:
            if use_lock:
                with repair_lock(blocking=False):
                    results = fix_missing_files(args.dry_run)
            else:
                results = fix_missing_files(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"{'[DRY RUN] ' if args.dry_run else ''}Removed {len(results['deleted_records'])} missing file records")

        elif args.fix_thumbnails:
            if use_lock:
                with repair_lock(blocking=False):
                    results = fix_missing_thumbnails(args.dry_run)
            else:
                results = fix_missing_thumbnails(args.dry_run)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"{'[DRY RUN] ' if args.dry_run else ''}Regenerated {len(results['regenerated'])} thumbnails")
                if results.get('failed'):
                    print(f"Failed: {len(results['failed'])}")

    except RepairLockError as e:
        print(f"Lock error: {e}", file=sys.stderr)
        sys.exit(2)  # Exit code 2 indicates lock conflict
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
