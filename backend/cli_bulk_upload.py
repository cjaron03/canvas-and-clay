"""Interactive admin bulk upload helper.

Flow:
- Admin logs in (CSRF + session)
- Optionally list existing artists
- Choose existing artist or create new artist + user (register -> promote to artist -> create artist -> assign user)
- Choose how to distribute photos (single artwork or one per file)
- Auto-build manifest and call /api/admin/bulk-upload

Usage (inside container, interactive):
    python cli_bulk_upload.py --zip /app/path/to/archive.zip
"""
import argparse
import getpass
import json
import os
import secrets
import string
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

import requests

ALLOWED_EXT = {'.jpg', '.jpeg', '.png', '.webp', '.avif'}
ICON_SPIN = ['|', '/', '-', '\\']
ICON_OK = "✓"
ICON_FAIL = "✗"


def step(msg):
    print(f"[..] {msg}")


def step_done(msg="done"):
    print(f"[{ICON_OK}] {msg}")


def step_fail(msg="failed"):
    print(f"[{ICON_FAIL}] {msg}")


def prompt(msg, default=None, secret=False, allow_empty=False):
    full = f"{msg} " + (f"[{default}] " if default is not None else "")
    while True:
        try:
            val = getpass.getpass(full) if secret else input(full)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        if val.lower().strip() == 'exit':
            print("Exiting.")
            sys.exit(0)
        if not val and default is not None:
            return default
        if not val and not allow_empty:
            print("Value required (or type 'exit' to quit).")
            continue
        return val


def get_csrf_token(session: requests.Session, base_url: str) -> str:
    resp = session.get(f"{base_url}/auth/csrf-token", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data.get('csrf_token')


def login(session: requests.Session, base_url: str, email: str, password: str) -> None:
    step("Fetching CSRF token...")
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/auth/login",
        json={'email': email, 'password': password},
        headers={'X-CSRFToken': csrf_token},
        timeout=15
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Login failed ({resp.status_code}): {resp.text}")
    step_done("Authenticated")


def list_artists(session: requests.Session, base_url: str):
    step("Fetching artists...")
    resp = session.get(f"{base_url}/api/admin/console/artists", timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to load artists ({resp.status_code}): {resp.text}")
    step_done("Artists loaded")
    return resp.json().get('artists', [])


def list_storage_locations(session: requests.Session, base_url: str):
    step("Fetching storage locations...")
    resp = session.get(f"{base_url}/api/storage", timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to load storage locations ({resp.status_code}): {resp.text}")
    data = resp.json().get('storage', [])
    step_done(f"Storage loaded ({len(data)} found)")
    return data


def list_artworks_by_artist_storage(session: requests.Session, base_url: str, artist_id: str, storage_id: str):
    """Fetch artworks for a specific artist/storage to detect duplicates."""
    resp = session.get(
        f"{base_url}/api/artworks",
        params={'artist_id': artist_id, 'storage_id': storage_id, 'per_page': 200},
        timeout=20
    )
    if resp.status_code != 200:
        return []
    return resp.json().get('artworks', [])


def check_user_exists(session, base_url, email):
    """Check if a user email already exists."""
    try:
        resp = session.get(f"{base_url}/api/admin/console/users", timeout=20)
        if resp.status_code == 200:
            users = resp.json().get('users', [])
            return any(u.get('email', '').lower() == email.lower() for u in users)
    except Exception:
        pass
    return False


def register_user(session, base_url, email, password):
    step(f"Registering user {email} ...")
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/auth/register",
        json={'email': email, 'password': password},
        headers={'X-CSRFToken': csrf_token},
        timeout=20
    )
    if resp.status_code != 201:
        raise RuntimeError(f"User registration failed ({resp.status_code}): {resp.text}")
    step_done("User created")
    return resp.json()['user']['id']


def promote_to_artist(session, base_url, user_id):
    step(f"Promoting user {user_id} to artist...")
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/api/admin/console/users/{user_id}/promote",
        headers={'X-CSRFToken': csrf_token},
        timeout=20
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Promote user {user_id} failed ({resp.status_code}): {resp.text}")
    step_done("User promoted")


def create_artist(session, base_url, payload):
    step(f"Creating artist {payload.get('artist_fname','')} {payload.get('artist_lname','')} ...")
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/api/artists",
        json=payload,
        headers={'X-CSRFToken': csrf_token},
        timeout=20
    )
    if resp.status_code != 201:
        raise RuntimeError(f"Create artist failed ({resp.status_code}): {resp.text}")
    step_done("Artist created")
    try:
        return resp.json()['artist']['id']
    except KeyError as e:
        raise RuntimeError(f"Unexpected API response format: missing {e}. Response: {resp.text[:200]}")


def assign_artist_user(session, base_url, artist_id, user_id):
    step(f"Linking artist {artist_id} to user {user_id} ...")
    csrf_token = get_csrf_token(session, base_url)
    resp = session.post(
        f"{base_url}/api/admin/artists/{artist_id}/assign-user",
        json={'user_id': user_id},
        headers={'X-CSRFToken': csrf_token},
        timeout=20
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Assign artist {artist_id} to user {user_id} failed ({resp.status_code}): {resp.text}")
    step_done("Artist linked to user")


def bulk_upload(session: requests.Session, base_url: str, zip_path: str) -> dict:
    file_size = os.path.getsize(zip_path)
    step(f"Uploading bulk zip ({file_size / 1024 / 1024:.2f} MB)...")
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
    step_done("Upload finished")
    return resp.json()


def filter_zip_files(zip_path):
    step("Scanning zip for images...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        files = []
        for name in zf.namelist():
            if name.endswith('/'):
                continue
            base = os.path.basename(name)
            ext = Path(base).suffix.lower()
            # Skip macOS metadata files and hidden files
            if base.startswith('._') or base.startswith('.'):
                continue
            # Skip files in __MACOSX directory (macOS metadata)
            if '__MACOSX' in name:
                continue
            # Only include valid image extensions
            if ext not in ALLOWED_EXT:
                continue
            files.append(name)
    if not files:
        raise RuntimeError("Zip contains no supported image files (JPG, JPEG, PNG, WebP, AVIF).")
    step_done(f"Found {len(files)} image(s)")
    return files


def resolve_duplicates(files):
    """Prompt for duplicate handling and return final file list (full paths)."""
    counts = {}
    for f in files:
        base = Path(f).name
        counts[base] = counts.get(base, 0) + 1
    dup_basenames = [b for b, c in counts.items() if c > 1]
    if not dup_basenames:
        return files

    ans = prompt("Duplicate filenames detected. Override (keep last) or suffix? [o/s]:", default="s").lower()
    strategy = 'override' if ans.startswith('o') else 'suffix'

    if strategy == 'override':
        latest = {}
        for f in files:
            latest[Path(f).name] = f  # last occurrence wins
        return list(latest.values())
    else:
        # Suffix strategy: keep full paths; backend disambiguates by exact path
        return files


def build_manifest(files, artist_id, artist_email, storage_id, mode, title_base=None, use_filenames=True):
    step("Building manifest...")
    manifest = {
        "default_storage_id": storage_id,
        "artists": [],
        "artworks": [],
        "photos": []
    }
    art_key_map = {}

    def safe_title(name):
        stem = Path(name).stem
        cleaned = stem.replace('_', ' ').replace('-', ' ').strip() or stem or "Untitled"
        return cleaned[:50]

    duplicate_strategy = 'ask'
    duplicate_counts = {}

    if mode == 'single':
        art_key = "art-1"
        manifest["artworks"].append({
            "key": art_key,
            "title": (title_base or "Bulk Upload")[:50],
            "artist_id": artist_id,
            "artist_email": artist_email,
            "storage_id": storage_id
        })
        art_key_map[art_key] = True
        for idx, f in enumerate(files, start=1):
            original_name = f  # preserve path within zip so backend can find it
            base_name = Path(f).name

            if base_name in duplicate_counts:
                duplicate_counts[base_name] += 1
                # Prompt once on duplicates (affects titles only; filename stays original)
                if duplicate_strategy == 'ask':
                    ans = prompt("Duplicate filenames detected. Override or suffix? [o/s]:", default="s").lower()
                    duplicate_strategy = 'override' if ans.startswith('o') else 'suffix'
                if duplicate_strategy == 'suffix':
                    stem = Path(base_name).stem
                    ext = Path(base_name).suffix
                    base_name = f"{stem} ({duplicate_counts[base_name]}){ext}"
                # override keeps the same base_name
            else:
                duplicate_counts[base_name] = 0

            manifest["photos"].append({
                "filename": original_name,
                "artwork_key": art_key,
                "is_primary": idx == 1
            })
    else:
        for idx, f in enumerate(files, start=1):
            original_name = f  # preserve path within zip so backend can find it
            base_name = Path(f).name

            if base_name in duplicate_counts:
                duplicate_counts[base_name] += 1
                if duplicate_strategy == 'ask':
                    ans = prompt("Duplicate filenames detected. Override or suffix? [o/s]:", default="s").lower()
                    duplicate_strategy = 'override' if ans.startswith('o') else 'suffix'
                if duplicate_strategy == 'suffix':
                    stem = Path(base_name).stem
                    ext = Path(base_name).suffix
                    base_name = f"{stem} ({duplicate_counts[base_name]}){ext}"
                # override keeps base_name
            else:
                duplicate_counts[base_name] = 0

            art_key = f"art-{idx}"
            title = safe_title(base_name) if use_filenames else f"{title_base or 'Artwork'} {idx}"
            manifest["artworks"].append({
                "key": art_key,
                "title": title[:50],
                "artist_id": artist_id,
                "artist_email": artist_email,
                "storage_id": storage_id
            })
            manifest["photos"].append({
                "filename": original_name,
                "artwork_key": art_key,
                "is_primary": True
            })
            art_key_map[art_key] = True
    step_done("Manifest built")
    return manifest


def pick_storage(storage_list, default_storage):
    if not storage_list:
        print(f"No storage locations found. Using default: {default_storage}")
        return default_storage

    page = 0
    per_page = 4
    total_pages = (len(storage_list) + per_page - 1) // per_page

    while True:
        start = page * per_page
        end = start + per_page
        slice_ = storage_list[start:end]
        print(f"\nStorage page {page+1}/{total_pages}:")
        for idx, s in enumerate(slice_, start=1):
            print(f"  {idx}) {s.get('id')} | {s.get('location')} | {s.get('type')}")
        choice = prompt(
            "Select storage (number/id), n=next, p=prev, Enter=default "
            f"[{default_storage}]:",
            default=None,
            allow_empty=True
        )
        if choice == "" and default_storage:
            return default_storage
        if choice.lower() in ("n", "next"):
            if page + 1 < total_pages:
                page += 1
            else:
                print("Already at last page.")
            continue
        if choice.lower() in ("p", "prev"):
            if page > 0:
                page -= 1
            else:
                print("Already at first page.")
            continue
        # direct id match
        match = next((s for s in storage_list if str(s.get('id')) == choice), None)
        if match:
            return match.get('id')
        # number on current page
        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(slice_):
                return slice_[num - 1].get('id')
        print("Invalid selection. Try again (or type 'exit' to quit).")


def stitch_zip_with_manifest(src_zip, manifest):
    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(src_zip, 'r') as zin, zipfile.ZipFile(tmp_zip, 'w') as zout:
        for item in zin.infolist():
            if item.filename.endswith('/'):
                continue
            zout.writestr(item, zin.read(item.filename))
        zout.writestr('manifest.json', json.dumps(manifest, indent=2))
    tmp_zip.close()
    return tmp_zip.name


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def main():
    parser = argparse.ArgumentParser(description="Interactive admin bulk upload helper")
    parser.add_argument('--zip', required=True, help='Path to zip archive containing images (manifest will be generated)')
    parser.add_argument('--base-url', default=os.getenv('API_BASE_URL', 'http://backend:5000'), help='API base URL (default: http://backend:5000)')
    parser.add_argument('--default-storage', default='STOR001', help='Default storage ID for artworks')
    parser.add_argument('--mode', choices=['single', 'per-file'], help='Artwork distribution mode (single=all photos on one artwork, per-file=one artwork per photo)')
    parser.add_argument('--artist-email', help='Force an existing artist email (skip interactive selection)')
    parser.add_argument('--interactive', action='store_true', default=True, help='Run interactively (default)')
    args = parser.parse_args()

    if not os.path.exists(args.zip):
        print(f"Zip not found: {args.zip}", file=sys.stderr)
        sys.exit(1)

    base_url = args.base_url.rstrip('/')
    session = requests.Session()

    try:
        admin_email = prompt("Admin email:")
        admin_password = prompt("Admin password:", secret=True)
        print(f"[{datetime.now().isoformat()}] Logging in as {admin_email} ...")
        login(session, base_url, admin_email, admin_password)
        print("Login successful.")

        files = filter_zip_files(args.zip)

        # Fetch artists for lookup
        artists = list_artists(session, base_url)
        if artists:
            print("Existing artists (id | name | email | linked_user_email):")
            for a in artists:
                print(f"- {a.get('id')} | {a.get('name')} | {a.get('email')} | user:{a.get('user_email')}")

        # Choose artist
        chosen_artist_id = None
        chosen_artist_email = None

        # Resolve duplicate filenames if any
        files = resolve_duplicates(files)

        use_existing = prompt("Use existing artist? [y/n]:", default="y").lower().startswith('y')
        if use_existing:
            if args.artist_email:
                match = next((a for a in artists if (a.get('email') or '').lower() == args.artist_email.lower()), None)
                if not match:
                    raise RuntimeError(f"Artist with email {args.artist_email} not found")
                chosen_artist_id = match['id']
                chosen_artist_email = match['email']
            else:
                while not chosen_artist_id:
                    picked = prompt("Enter artist email or id (or 'exit' to quit):", allow_empty=False)
                    match = next((a for a in artists if str(a.get('id')) == picked or (a.get('email') or '').lower() == picked.lower()), None)
                    if match:
                        chosen_artist_id = match['id']
                        chosen_artist_email = match['email']
                    else:
                        print("No matching artist found. Try again.")
        else:
            # Create new user
            new_email = prompt("New artist user email:")

            # Check if user already exists
            if check_user_exists(session, base_url, new_email):
                step_fail(f"User {new_email} already exists!")
                print("Please use 'Use existing artist' flow or choose a different email.")
                raise RuntimeError(f"User {new_email} already exists. Cannot create duplicate.")

            new_password = prompt("Artist user password (leave blank to auto-generate):", secret=True, allow_empty=True)
            if not new_password:
                new_password = generate_password()
                print(f"Generated password: {new_password}")

            user_id = register_user(session, base_url, new_email, new_password)
            promote_to_artist(session, base_url, user_id)

            first_name = prompt("Artist first name:")
            last_name = prompt("Artist last name:")
            site = prompt("Artist site (optional, Enter to skip):", allow_empty=True)
            bio = prompt("Artist bio (optional, Enter to skip):", allow_empty=True)
            phone = prompt("Artist phone (optional, format (123)-456-7890, Enter to skip):", allow_empty=True)

            artist_payload = {
                "artist_fname": first_name,
                "artist_lname": last_name,
                "email": new_email,
                "artist_site": site or None,
                "artist_bio": bio or None,
                "artist_phone": phone or None,
                "user_id": user_id
            }
            artist_id = create_artist(session, base_url, artist_payload)
            assign_artist_user(session, base_url, artist_id, user_id)
            chosen_artist_id = artist_id
            chosen_artist_email = new_email

        # Artwork distribution
        # Storage selection with paging (4 per page)
        storage_list = list_storage_locations(session, base_url)
        storage_id = pick_storage(storage_list, default_storage=args.default_storage)

        mode = args.mode or prompt("Artwork mode? (single/per-file):", default="single").strip().lower()
        if mode not in ('single', 'per-file'):
            mode = 'single'

        title_base = None
        use_filenames = True
        if mode == 'single':
            title_base = prompt("Artwork title for all photos:", default="Bulk Upload")
        else:
            use_filenames_answer = prompt("Use filenames as titles? [y/n]:", default="y").lower().startswith('y')
            use_filenames = use_filenames_answer
            if not use_filenames:
                title_base = prompt("Base title prefix:", default="Artwork")

        manifest = build_manifest(
            files=files,
            artist_id=chosen_artist_id,
            artist_email=chosen_artist_email,
            storage_id=storage_id,
            mode=mode,
            title_base=title_base,
            use_filenames=use_filenames
        )

        # Detect duplicates before upload and ask for handling strategy
        existing_artworks = list_artworks_by_artist_storage(session, base_url, chosen_artist_id, storage_id)
        existing_titles = {a.get('title', '').strip().lower() for a in existing_artworks}
        manifest_titles = {a.get('title', '').strip().lower() for a in manifest.get('artworks', [])}
        duplicate_titles = sorted({t for t in manifest_titles if t and t in existing_titles})

        duplicate_policy = 'suffix'
        if duplicate_titles:
            print("Duplicates detected for this artist/storage:")
            for t in duplicate_titles:
                print(f"  - {t}")
            dup_choice = prompt("Duplicate handling? override (delete+replace) or suffix new? [o/s]:", default="s").lower()
            duplicate_policy = 'override' if dup_choice.startswith('o') else 'suffix'

        manifest['duplicate_policy'] = duplicate_policy

        zip_with_manifest = stitch_zip_with_manifest(args.zip, manifest)
        print(f"Uploading bulk zip ({zip_with_manifest}) ...")
        result = bulk_upload(session, base_url, zip_with_manifest)

        summary = result.get('summary', {})
        print("Bulk upload complete.")
        print(f"- Artists created:  {summary.get('artists_created', 0)} (existing: {summary.get('artists_existing', 0)})")
        print(f"- Artworks created: {summary.get('artworks_created', 0)} (existing: {summary.get('artworks_existing', 0)})")
        print(f"- Photos created:   {summary.get('photos_created', 0)}")
        if summary.get('warnings'):
            print(f"- Warnings:         {summary.get('warnings')}")
        if summary.get('errors'):
            print(f"- Errors:           {summary.get('errors')}")

        warnings = result.get('results', {}).get('warnings', []) or result.get('warnings', []) or []
        errors = (result.get('errors') or []) + (result.get('results', {}).get('errors', []) or [])

        if warnings:
            print("Warnings:")
            for warn in warnings:
                scope = warn.get('scope')
                message = warn.get('message')
                detail = warn.get('detail')
                entry = ""
                if isinstance(detail, dict):
                    entry = detail.get('entry') or detail.get('filename') or ''
                print(f"  - [{scope}] {message} {entry}")

        if errors:
            print("Errors:")
            for err in errors:
                if isinstance(err, str):
                    print(f"  - {err}")
                    continue
                scope = err.get('scope')
                message = err.get('message')
                detail = err.get('detail')
                entry = ""
                if isinstance(detail, dict):
                    entry = detail.get('entry') or detail.get('filename') or ''
                print(f"  - [{scope}] {message} {entry}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
