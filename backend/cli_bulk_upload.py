"""CLI helper to call the admin bulk upload API from inside the backend container.

Usage (inside docker):
    python cli_bulk_upload.py --zip /path/to/archive.zip --admin-email admin@example.com --admin-password '...' --base-url http://backend:5000
"""
import argparse
import os
import sys
import requests
import zipfile
import json
import tempfile
from datetime import datetime


def get_csrf_token(session: requests.Session, base_url: str) -> str:
    resp = session.get(f"{base_url}/auth/csrf-token", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data.get('csrf_token')


def login(session: requests.Session, base_url: str, email: str, password: str) -> None:
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/auth/login",
        json={'email': email, 'password': password},
        headers={'X-CSRFToken': csrf_token},
        timeout=15
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Login failed ({resp.status_code}): {resp.text}")


def bulk_upload(session: requests.Session, base_url: str, zip_path: str) -> dict:
    csrf_token = get_csrf_token(session, base_url)
    with open(zip_path, 'rb') as fh:
        files = {'file': (os.path.basename(zip_path), fh, 'application/zip')}
        resp = session.post(
            f"{base_url}/api/admin/bulk-upload",
            files=files,
            headers={'X-CSRFToken': csrf_token},
            timeout=600
        )
    if resp.status_code not in (200, 207):
        raise RuntimeError(f"Bulk upload failed ({resp.status_code}): {resp.text}")
    return resp.json()


def _slug_title_from_filename(name: str) -> str:
    stem = os.path.splitext(os.path.basename(name))[0]
    cleaned = stem.replace('_', ' ').replace('-', ' ').strip()
    title = cleaned or stem or "Untitled"
    return title[:50]  # match artwork_ttl length constraint


def generate_manifest(zip_path: str, storage_id: str, artist_email: str, artist_name: str) -> str:
    """Create a manifest.json and return path to a new zip that includes it."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        filenames = [n for n in zf.namelist() if not n.endswith('/')]

    allowed_ext = {'.jpg', '.jpeg', '.png', '.webp', '.avif'}
    files = []
    seen = set()
    for name in filenames:
        base = os.path.basename(name)
        ext = os.path.splitext(base)[1].lower()
        if base.startswith('._') or base.startswith('.'):
            # Skip macOS resource forks/hidden files
            continue
        if ext not in allowed_ext:
            continue
        if base in seen:
            continue
        seen.add(base)
        files.append(name)

    if not files:
        raise RuntimeError("Zip contains no supported image files (JPG, PNG, WebP, AVIF).")

    artist_first, artist_last = (artist_name.split(' ', 1) + [''])[:2]
    manifest = {
        "default_storage_id": storage_id,
        "artists": [
            {
                "key": "auto-artist",
                "first_name": artist_first or "Auto",
                "last_name": artist_last or "Uploader",
                "email": artist_email or None
            }
        ],
        "artworks": [],
        "photos": []
    }

    for idx, fname in enumerate(files, start=1):
        art_key = f"art-{idx}"
        manifest["artworks"].append({
            "key": art_key,
            "title": _slug_title_from_filename(fname),
            "artist_key": "auto-artist",
            "storage_id": storage_id
        })
        manifest["photos"].append({
            "filename": os.path.basename(fname),
            "artwork_key": art_key,
            "is_primary": idx == 1
        })

    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(zip_path, 'r') as zin, zipfile.ZipFile(tmp_zip, 'w') as zout:
        for item in zin.infolist():
            if item.filename.endswith('/'):
                continue
            zout.writestr(item, zin.read(item.filename))
        zout.writestr('manifest.json', json.dumps(manifest, indent=2))
    tmp_zip.close()
    return tmp_zip.name


def ensure_manifest(zip_path: str, auto_mode: bool, storage_id: str, artist_email: str, artist_name: str) -> str:
    """Ensure the zip has a manifest; auto-generate if absent."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        if 'manifest.json' in zf.namelist():
            return zip_path

    if not auto_mode:
        # Prompt the user
        print("manifest.json not found in the zip.")
        answer = input("Auto-generate a manifest from image filenames? [y/N]: ").strip().lower()
        if answer not in ('y', 'yes'):
            raise RuntimeError("Manifest required. Add manifest.json to the zip or rerun with --auto-manifest.")
        if not storage_id:
            storage_id = input("Enter default storage_id (e.g., STOR001): ").strip()
        if not artist_email:
            artist_email = input("Enter artist email (optional, press Enter to skip): ").strip()
        if not artist_name:
            artist_name = input("Enter artist name (e.g., Auto Uploader): ").strip() or "Auto Uploader"

    if not storage_id:
        raise RuntimeError("Storage ID is required to auto-generate a manifest.")

    auto_zip = generate_manifest(zip_path, storage_id, artist_email, artist_name or "Auto Uploader")
    print(f"Generated manifest.json and built new zip: {auto_zip}")
    return auto_zip


def main():
    parser = argparse.ArgumentParser(description="Admin bulk upload client (zip + manifest.json)")
    parser.add_argument('--zip', required=True, help='Path to zip archive containing manifest.json and images')
    parser.add_argument('--admin-email', required=True, help='Admin email for authentication')
    parser.add_argument('--admin-password', required=True, help='Admin password for authentication')
    parser.add_argument('--base-url', default=os.getenv('API_BASE_URL', 'http://backend:5000'), help='API base URL (default: http://backend:5000)')
    parser.add_argument('--auto-manifest', action='store_true', help='Auto-generate manifest.json if missing')
    parser.add_argument('--default-storage', help='Storage ID to use when auto-generating manifest (e.g., STOR001)')
    parser.add_argument('--artist-email', help='Artist email to use when auto-generating manifest')
    parser.add_argument('--artist-name', help='Artist name to use when auto-generating manifest (e.g., "Auto Uploader")')
    args = parser.parse_args()

    if not os.path.exists(args.zip):
        print(f"Zip not found: {args.zip}", file=sys.stderr)
        sys.exit(1)

    base_url = args.base_url.rstrip('/')
    session = requests.Session()

    try:
        zip_with_manifest = ensure_manifest(
            args.zip,
            auto_mode=args.auto_manifest,
            storage_id=args.default_storage,
            artist_email=args.artist_email,
            artist_name=args.artist_name
        )

        print(f"[{datetime.now().isoformat()}] Logging in as {args.admin_email} ...")
        login(session, base_url, args.admin_email, args.admin_password)
        print("Login successful.")

        print(f"Uploading bulk zip ({zip_with_manifest}) ...")
        result = bulk_upload(session, base_url, zip_with_manifest)

        summary = result.get('summary', {})
        print("Bulk upload complete.")
        print(f"- Artists created:  {summary.get('artists_created', 0)} (existing: {summary.get('artists_existing', 0)})")
        print(f"- Artworks created: {summary.get('artworks_created', 0)} (existing: {summary.get('artworks_existing', 0)})")
        print(f"- Photos created:   {summary.get('photos_created', 0)}")
        if summary.get('errors'):
            print(f"- Errors:           {summary.get('errors')}")
        errors = result.get('results', {}).get('errors', [])
        if errors:
            print("Error details:")
            for err in errors:
                print(f"- [{err.get('scope')}] {err.get('message')}: {err.get('detail')}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
