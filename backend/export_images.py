#!/usr/bin/env python3
"""Export uploaded images to a zip file for cross-deployment sync.

Usage:
    python3 export_images.py --output images.zip
    python3 export_images.py --output images.zip --include-thumbnails

Features:
    - Exports all images from /app/uploads to a zip file
    - Optionally includes thumbnail files
    - Creates manifest.json with file checksums for verification
    - Preserves directory structure
"""

import argparse
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone

UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


def calculate_checksum(filepath):
    """Calculate SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def is_thumbnail(filename):
    """Check if file is a thumbnail."""
    return '_thumb' in filename or filename.startswith('thumb_')


def export_images(output_file, include_thumbnails=False):
    """Export images to a zip file.

    Args:
        output_file: Path to output zip file
        include_thumbnails: Whether to include thumbnail files
    """
    if not os.path.exists(UPLOADS_DIR):
        print(f"Uploads directory not found: {UPLOADS_DIR}")
        print("No images to export.")
        return

    manifest = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "include_thumbnails": include_thumbnails,
        "files": []
    }

    file_count = 0
    total_size = 0

    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(UPLOADS_DIR):
            # Skip .gitkeep
            files = [f for f in files if f != '.gitkeep']

            for filename in files:
                # Skip thumbnails if not requested
                if not include_thumbnails and is_thumbnail(filename):
                    continue

                filepath = os.path.join(root, filename)
                # Get relative path from uploads dir
                arcname = os.path.relpath(filepath, UPLOADS_DIR)

                # Calculate checksum
                checksum = calculate_checksum(filepath)
                file_size = os.path.getsize(filepath)

                # Add to manifest
                manifest["files"].append({
                    "path": arcname,
                    "checksum": checksum,
                    "size": file_size
                })

                # Add to zip
                zipf.write(filepath, arcname)
                file_count += 1
                total_size += file_size

                print(f"  Added: {arcname} ({file_size:,} bytes)")

        # Add manifest to zip
        manifest["total_files"] = file_count
        manifest["total_size"] = total_size
        zipf.writestr("manifest.json", json.dumps(manifest, indent=2))

    print("-" * 60)
    print(f"Exported {file_count} files to {output_file}")
    print(f"Total size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
    if not include_thumbnails:
        print("(Thumbnails excluded - use --include-thumbnails to include)")


def main():
    parser = argparse.ArgumentParser(
        description="Export uploaded images to zip for cross-deployment sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output zip file path"
    )
    parser.add_argument(
        "--include-thumbnails",
        action="store_true",
        help="Include thumbnail files in export"
    )

    args = parser.parse_args()
    export_images(args.output, args.include_thumbnails)


if __name__ == "__main__":
    main()
