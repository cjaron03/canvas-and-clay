#!/usr/bin/env python3
"""
Canvas & Clay Repair Scanner

Comprehensive system scanner that outputs bash-friendly key=value pairs.
Used by setup.sh repair wizard for reliable issue detection.

Output format (eval-able by bash):
    ORPHANED_COUNT=2
    MISSING_FILES_COUNT=17
    MISSING_THUMBNAILS_COUNT=0
    DB_CONNECTION=ok
    MIGRATION_STATUS=ok
    MIGRATION_HEADS=1
    DISK_SPACE_OK=true
    DISK_SPACE_FREE_MB=5000

Usage:
    eval "$(python3 repair_scan.py)"
"""

import os
import sys
import subprocess
import shutil

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


def check_database_connection():
    """Check if database connection is working."""
    try:
        from app import app, db
        with app.app_context():
            db.session.execute(db.text('SELECT 1'))
        return 'ok'
    except Exception:
        return 'fail'


def check_pii_encryption_key():
    """Validate PII_ENCRYPTION_KEY is set and functional.

    Returns:
        dict with:
            PII_KEY_STATUS: 'ok', 'missing', 'empty', 'placeholder', 'invalid'
            PII_KEY_SOURCE: 'env-key', 'secret-key', 'ephemeral', 'none'
    """
    results = {
        'PII_KEY_STATUS': 'unknown',
        'PII_KEY_SOURCE': 'none'
    }

    key_env = os.environ.get('PII_ENCRYPTION_KEY', '')
    secret_env = os.environ.get('SECRET_KEY', '')

    # Check if key exists
    if not key_env and not secret_env:
        results['PII_KEY_STATUS'] = 'missing'
        return results

    # Determine source
    if key_env:
        results['PII_KEY_SOURCE'] = 'env-key'
        key_value = key_env
    else:
        results['PII_KEY_SOURCE'] = 'secret-key'
        key_value = secret_env

    # Check for empty key
    if not key_value.strip():
        results['PII_KEY_STATUS'] = 'empty'
        return results

    # Check for placeholder values
    placeholder_values = [
        'PLACEHOLDER_PII_KEY',
        'PLACEHOLDER',
        'changeme',
        'change_me',
        'your-key-here',
        'your_key_here',
        'xxx',
        'test',
        'dev'
    ]
    if key_value.strip().lower() in [p.lower() for p in placeholder_values]:
        results['PII_KEY_STATUS'] = 'placeholder'
        return results

    # Check minimum length (should be reasonably secure)
    if len(key_value) < 16:
        results['PII_KEY_STATUS'] = 'too_short'
        return results

    # Test actual encryption/decryption
    try:
        from encryption import _encrypt, _decrypt
        test_value = "repair_scan_test_string_12345"
        encrypted = _encrypt(test_value)
        decrypted = _decrypt(encrypted)

        if decrypted == test_value:
            results['PII_KEY_STATUS'] = 'ok'
        else:
            results['PII_KEY_STATUS'] = 'invalid'
    except Exception as e:
        results['PII_KEY_STATUS'] = 'error'

    return results


def check_data_integrity():
    """Run data integrity scans and return counts."""
    results = {
        'ORPHANED_COUNT': 0,
        'ORPHANED_SCAN_SKIPPED': 'false',
        'ORPHANED_SKIP_REASON': '',
        'MISSING_FILES_COUNT': 0,
        'MISSING_THUMBNAILS_COUNT': 0
    }

    try:
        from repair_checks import (
            scan_orphaned_files,
            scan_missing_files,
            scan_missing_thumbnails
        )

        orphaned = scan_orphaned_files()
        if orphaned.get('skipped'):
            results['ORPHANED_SCAN_SKIPPED'] = 'true'
            results['ORPHANED_SKIP_REASON'] = orphaned.get('skip_reason', 'Unknown')[:80]
        else:
            results['ORPHANED_COUNT'] = orphaned.get('count', 0)

        missing = scan_missing_files()
        results['MISSING_FILES_COUNT'] = missing.get('count', 0)

        thumbnails = scan_missing_thumbnails()
        results['MISSING_THUMBNAILS_COUNT'] = thumbnails.get('count', 0)

    except Exception as e:
        # If scans fail, report error but don't crash
        print(f"SCAN_ERROR={str(e)[:50]}", file=sys.stderr)

    return results


def check_migrations():
    """Check migration status for multiple heads or pending migrations."""
    results = {
        'MIGRATION_STATUS': 'unknown',
        'MIGRATION_HEADS': 0,
        'PENDING_MIGRATIONS': 0
    }

    try:
        # Check for multiple heads
        heads_result = subprocess.run(
            ['flask', 'db', 'heads'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if heads_result.returncode == 0:
            # Count number of revision IDs (lines with revision hashes)
            heads_output = heads_result.stdout.strip()
            head_count = len([
                line for line in heads_output.split('\n')
                if line.strip() and not line.startswith('(')
            ])
            results['MIGRATION_HEADS'] = max(head_count, 1)

            if 'Multiple' in heads_result.stderr or head_count > 1:
                results['MIGRATION_STATUS'] = 'multiple_heads'
            else:
                results['MIGRATION_STATUS'] = 'ok'
        else:
            results['MIGRATION_STATUS'] = 'error'

        # Check for pending migrations
        current_result = subprocess.run(
            ['flask', 'db', 'current'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if 'head' not in current_result.stdout.lower():
            # Not at head, might have pending migrations
            results['PENDING_MIGRATIONS'] = 1

    except subprocess.TimeoutExpired:
        results['MIGRATION_STATUS'] = 'timeout'
    except Exception:
        results['MIGRATION_STATUS'] = 'error'

    return results


def check_disk_space():
    """Check available disk space in uploads directory."""
    results = {
        'DISK_SPACE_OK': 'true',
        'DISK_SPACE_FREE_MB': 0
    }

    try:
        # Ensure uploads directory exists
        if not os.path.exists(UPLOADS_DIR):
            os.makedirs(UPLOADS_DIR, exist_ok=True)

        usage = shutil.disk_usage(UPLOADS_DIR)
        free_mb = usage.free // (1024 * 1024)
        results['DISK_SPACE_FREE_MB'] = free_mb

        # Warn if less than 100MB free
        if free_mb < 100:
            results['DISK_SPACE_OK'] = 'false'

    except Exception:
        results['DISK_SPACE_OK'] = 'unknown'

    return results


def check_directories():
    """Check if required directories exist."""
    results = {
        'UPLOADS_DIR_EXISTS': 'true' if os.path.isdir(UPLOADS_DIR) else 'false',
        'ARTWORKS_DIR_EXISTS': 'true' if os.path.isdir(
            os.path.join(UPLOADS_DIR, 'artworks')
        ) else 'false',
        'THUMBNAILS_DIR_EXISTS': 'true' if os.path.isdir(
            os.path.join(UPLOADS_DIR, 'thumbnails')
        ) else 'false'
    }
    return results


def main():
    """Run all checks and output bash-friendly results."""
    results = {}

    # 1. Database connection
    results['DB_CONNECTION'] = check_database_connection()

    # 2. Data integrity (only if DB is connected)
    if results['DB_CONNECTION'] == 'ok':
        results.update(check_data_integrity())
        results.update(check_migrations())
    else:
        results['ORPHANED_COUNT'] = 0
        results['MISSING_FILES_COUNT'] = 0
        results['MISSING_THUMBNAILS_COUNT'] = 0
        results['MIGRATION_STATUS'] = 'unknown'
        results['MIGRATION_HEADS'] = 0
        results['PENDING_MIGRATIONS'] = 0

    # 3. Disk space
    results.update(check_disk_space())

    # 4. Directories
    results.update(check_directories())

    # 5. PII Encryption Key validation
    results.update(check_pii_encryption_key())

    # Output in bash-friendly format
    for key, value in sorted(results.items()):
        # Ensure values are safe for bash eval
        safe_value = str(value).replace("'", "").replace('"', '').replace('\n', ' ')
        print(f"{key}={safe_value}")


if __name__ == '__main__':
    main()
