#!/usr/bin/env python3
"""Import images from a zip file exported by export_images.py.

Usage:
    python3 import_images.py --input images.zip --dry-run
    python3 import_images.py --input images.zip
    python3 import_images.py --input images.zip --overwrite

Features:
    - Extracts images to /app/uploads
    - Verifies checksums if manifest.json present
    - Skips existing files by default (use --overwrite to replace)
    - Dry-run mode to preview changes
"""

import argparse
import hashlib
import json
import os
import sys
import zipfile

UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


def calculate_checksum(filepath):
    """Calculate SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def import_images(input_file, dry_run=False, overwrite=False):
    """Import images from a zip file.

    Args:
        input_file: Path to zip file from export_images.py
        dry_run: If True, preview without making changes
        overwrite: If True, overwrite existing files
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    print("=" * 60)
    print("IMAGE IMPORT")
    print("=" * 60)
    print(f"Import file: {input_file}")
    if dry_run:
        print("MODE: DRY RUN - no changes will be made")
    if overwrite:
        print("MODE: OVERWRITE - existing files will be replaced")
    print("-" * 60)

    # Ensure uploads directory exists
    if not dry_run:
        os.makedirs(UPLOADS_DIR, exist_ok=True)

    manifest = None
    checksums = {}

    with zipfile.ZipFile(input_file, 'r') as zipf:
        # Try to load manifest
        if 'manifest.json' in zipf.namelist():
            manifest_data = zipf.read('manifest.json')
            manifest = json.loads(manifest_data)
            print(f"Manifest found - exported at: {manifest.get('exported_at', 'unknown')}")
            print(f"Total files in archive: {manifest.get('total_files', 'unknown')}")

            # Build checksum lookup
            for file_info in manifest.get('files', []):
                checksums[file_info['path']] = file_info['checksum']

        print("-" * 60)

        extracted = 0
        skipped = 0
        errors = 0

        for member in zipf.namelist():
            # Skip manifest
            if member == 'manifest.json':
                continue

            # Skip directories
            if member.endswith('/'):
                continue

            dest_path = os.path.join(UPLOADS_DIR, member)

            # Check if file exists
            if os.path.exists(dest_path) and not overwrite:
                print(f"  Skipped (exists): {member}")
                skipped += 1
                continue

            # Create parent directories
            dest_dir = os.path.dirname(dest_path)
            if not dry_run and dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            # Extract file
            if not dry_run:
                try:
                    zipf.extract(member, UPLOADS_DIR)

                    # Verify checksum if available
                    if member in checksums:
                        actual_checksum = calculate_checksum(dest_path)
                        if actual_checksum != checksums[member]:
                            print(f"  WARNING: Checksum mismatch for {member}")
                            errors += 1
                            continue

                    print(f"  Extracted: {member}")
                    extracted += 1
                except Exception as e:
                    print(f"  Error extracting {member}: {e}")
                    errors += 1
            else:
                print(f"  Would extract: {member}")
                extracted += 1

    print("-" * 60)
    print(f"Summary: {extracted} extracted, {skipped} skipped, {errors} errors")
    if dry_run:
        print("(DRY RUN - no changes were made)")


def main():
    parser = argparse.ArgumentParser(
        description="Import images from zip export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input zip file path"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files"
    )

    args = parser.parse_args()
    import_images(args.input, args.dry_run, args.overwrite)


if __name__ == "__main__":
    main()
