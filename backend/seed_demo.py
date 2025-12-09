#!/usr/bin/env python3
"""Seed demo data for Canvas & Clay setup wizard.

Creates a complete demo dataset including:
- Demo users (artist, guest)
- Demo artist profile linked to artist user
- Demo storage location
- Demo artworks with generated placeholder images

Usage:
    python3 seed_demo.py

Or via the setup wizard API endpoint.
"""

import os
import sys
from datetime import datetime, timezone, date

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, bcrypt  # noqa: E402
from create_tbls import init_tables  # noqa: E402
from placeholder_generator import generate_placeholder_image, get_color_for_index  # noqa: E402
from upload_utils import process_upload  # noqa: E402


# Demo data configuration
DEMO_ARTIST_ID = "DEMO0001"
DEMO_STORAGE_ID = "DEMO001"

DEMO_USERS = [
    {
        "email": "artist@canvas-clay.local",
        "password": "DemoArtist2025!",
        "role": "artist",
        "link_to_artist": DEMO_ARTIST_ID
    },
    {
        "email": "guest@canvas-clay.local",
        "password": "GuestUser2025!",
        "role": "guest",
        "link_to_artist": None
    }
]

DEMO_ARTIST = {
    "artist_id": DEMO_ARTIST_ID,
    "first_name": "Demo",
    "last_name": "Artist",
    "email": "artist@canvas-clay.local",
    "bio": "This is a demo artist account for exploring Canvas & Clay features. "
           "Delete this artist and create your own to start managing your collection."
}

DEMO_STORAGE = {
    "storage_id": DEMO_STORAGE_ID,
    "location": "Demo Gallery",
    "storage_type": "wall"
}

DEMO_ARTWORKS = [
    {
        "artwork_num": "DEMOAW01",
        "title": "Blue Horizon",
        "medium": "Digital Placeholder",
        "size": "800x600",
        "color_index": 0
    },
    {
        "artwork_num": "DEMOAW02",
        "title": "Crimson Wave",
        "medium": "Digital Placeholder",
        "size": "800x600",
        "color_index": 1
    },
    {
        "artwork_num": "DEMOAW03",
        "title": "Forest Path",
        "medium": "Digital Placeholder",
        "size": "800x600",
        "color_index": 2
    },
    {
        "artwork_num": "DEMOAW04",
        "title": "Sunset Glow",
        "medium": "Digital Placeholder",
        "size": "800x600",
        "color_index": 3
    },
    {
        "artwork_num": "DEMOAW05",
        "title": "Violet Dreams",
        "medium": "Digital Placeholder",
        "size": "800x600",
        "color_index": 4
    }
]

SECURITY_WARNINGS = [
    "Change the admin password before production use",
    "Change or remove artist@canvas-clay.local (password: DemoArtist2025!)",
    "Change or remove guest@canvas-clay.local (password: GuestUser2025!)",
    "Delete demo artworks when adding your real collection",
    "Keep your PII_ENCRYPTION_KEY backed up safely"
]


def check_demo_data_exists(Artist, Artwork):
    """Check if demo data already exists.

    Returns:
        bool: True if demo data exists
    """
    artist = db.session.get(Artist, DEMO_ARTIST_ID)
    return artist is not None


def upsert_demo_storage(Storage):
    """Create or update demo storage location.

    Returns:
        Storage: The storage record
    """
    storage = db.session.get(Storage, DEMO_STORAGE["storage_id"])
    if not storage:
        storage = Storage(storage_id=DEMO_STORAGE["storage_id"])
        db.session.add(storage)

    storage.storage_loc = DEMO_STORAGE["location"]
    storage.storage_type = DEMO_STORAGE["storage_type"]
    return storage


def upsert_demo_artist(Artist):
    """Create or update demo artist.

    Returns:
        Artist: The artist record
    """
    artist = db.session.get(Artist, DEMO_ARTIST["artist_id"])
    if not artist:
        artist = Artist(artist_id=DEMO_ARTIST["artist_id"])
        db.session.add(artist)

    artist.artist_fname = DEMO_ARTIST["first_name"]
    artist.artist_lname = DEMO_ARTIST["last_name"]
    artist.artist_email = DEMO_ARTIST["email"]
    artist.artist_bio = DEMO_ARTIST["bio"]
    artist.is_deleted = False
    artist.date_deleted = None
    return artist


def upsert_demo_artwork(Artwork, artwork_data):
    """Create or update a demo artwork.

    Args:
        Artwork: Artwork model class
        artwork_data: Dict with artwork configuration

    Returns:
        Artwork: The artwork record
    """
    artwork = db.session.get(Artwork, artwork_data["artwork_num"])
    if not artwork:
        artwork = Artwork(artwork_num=artwork_data["artwork_num"])
        db.session.add(artwork)

    artwork.artwork_ttl = artwork_data["title"]
    artwork.artwork_medium = artwork_data["medium"]
    artwork.artwork_size = artwork_data["size"]
    artwork.artist_id = DEMO_ARTIST_ID
    artwork.storage_id = DEMO_STORAGE_ID
    artwork.date_created = date.today()
    artwork.is_viewable = True
    artwork.is_deleted = False
    artwork.date_deleted = None
    return artwork


def create_demo_user(user_data, Artist):
    """Create a demo user account.

    Args:
        user_data: Dict with user configuration
        Artist: Artist model class

    Returns:
        tuple: (User, was_created)
    """
    email = user_data["email"].strip().lower()

    # Check if user exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        return existing, False

    # Create new user
    hashed_password = bcrypt.generate_password_hash(user_data["password"]).decode('utf-8')
    user = User(
        email=email,
        hashed_password=hashed_password,
        role=user_data["role"],
        created_at=datetime.now(timezone.utc),
        is_active=True
    )
    db.session.add(user)
    db.session.flush()

    # Link to artist if specified
    if user_data.get("link_to_artist"):
        artist = db.session.get(Artist, user_data["link_to_artist"])
        if artist:
            artist.user_id = user.id

    return user, True


def generate_and_save_placeholder(ArtworkPhoto, artwork_data, admin_user_id):
    """Generate placeholder image and create ArtworkPhoto record.

    Args:
        ArtworkPhoto: ArtworkPhoto model class
        artwork_data: Dict with artwork configuration
        admin_user_id: ID of admin user for uploaded_by field

    Returns:
        ArtworkPhoto or None: The photo record if created
    """
    artwork_num = artwork_data["artwork_num"]

    # Check if photo already exists for this artwork
    existing = ArtworkPhoto.query.filter_by(artwork_num=artwork_num).first()
    if existing:
        return None

    # Generate placeholder image
    color = get_color_for_index(artwork_data["color_index"])
    image_bytes = generate_placeholder_image(
        width=800,
        height=600,
        background_color=color,
        text=artwork_data["title"]
    )

    # Process through upload pipeline (validates, creates thumbnail, saves files)
    try:
        result = process_upload(
            file_data=image_bytes,
            original_filename=f"{artwork_num}_placeholder.png"
        )
    except Exception as e:
        print(f"  Warning: Failed to create placeholder for {artwork_num}: {e}")
        return None

    # Create ArtworkPhoto record
    photo = ArtworkPhoto(
        photo_id=result["photo_id"],
        artwork_num=artwork_num,
        filename=result["filename"],
        file_path=result["file_path"],
        thumbnail_path=result["thumbnail_path"],
        file_size=result["file_size"],
        mime_type=result["mime_type"],
        width=result["width"],
        height=result["height"],
        uploaded_at=datetime.now(timezone.utc),
        uploaded_by=admin_user_id,
        is_primary=True
    )
    db.session.add(photo)
    return photo


def seed_demo_data():
    """Seed complete demo dataset.

    Returns:
        dict: Summary of created items and security warnings
    """
    with app.app_context():
        Artist, Artwork, Storage, _, _, _, ArtworkPhoto = init_tables(db)

        # Check if demo data already exists
        if check_demo_data_exists(Artist, Artwork):
            print("Demo data already exists. Skipping seed.")
            return {
                "success": True,
                "skipped": True,
                "message": "Demo data already exists",
                "created": {
                    "users": 0,
                    "artists": 0,
                    "artworks": 0,
                    "photos": 0
                },
                "security_warnings": SECURITY_WARNINGS
            }

        # Get admin user for uploaded_by field
        admin_user = User.query.filter_by(role="admin").first()
        admin_user_id = admin_user.id if admin_user else None

        created_counts = {
            "users": 0,
            "artists": 0,
            "artworks": 0,
            "photos": 0
        }

        print("Seeding demo data...")

        # 1. Create storage
        print("  Creating demo storage...")
        upsert_demo_storage(Storage)
        db.session.flush()

        # 2. Create artist
        print("  Creating demo artist...")
        upsert_demo_artist(Artist)
        db.session.flush()
        created_counts["artists"] = 1

        # 3. Create artworks
        print("  Creating demo artworks...")
        for artwork_data in DEMO_ARTWORKS:
            upsert_demo_artwork(Artwork, artwork_data)
        db.session.flush()
        created_counts["artworks"] = len(DEMO_ARTWORKS)

        # 4. Create users (after artist so we can link them)
        print("  Creating demo users...")
        for user_data in DEMO_USERS:
            user, was_created = create_demo_user(user_data, Artist)
            if was_created:
                created_counts["users"] += 1
                print(f"    Created {user_data['role']} user: {user_data['email']}")

        db.session.flush()

        # 5. Generate placeholder images
        print("  Generating placeholder images...")
        for artwork_data in DEMO_ARTWORKS:
            photo = generate_and_save_placeholder(ArtworkPhoto, artwork_data, admin_user_id)
            if photo:
                created_counts["photos"] += 1
                print(f"    Created placeholder for: {artwork_data['title']}")

        # Commit all changes
        db.session.commit()

        print("\nDemo data seeded successfully.")
        print(f"  Users: {created_counts['users']}")
        print(f"  Artists: {created_counts['artists']}")
        print(f"  Artworks: {created_counts['artworks']}")
        print(f"  Photos: {created_counts['photos']}")

        return {
            "success": True,
            "skipped": False,
            "created": created_counts,
            "security_warnings": SECURITY_WARNINGS
        }


def check_setup_status():
    """Check if setup is required (database is empty).

    Returns:
        dict: Setup status information
    """
    # Example data artist IDs seeded by migration (should be excluded from setup check)
    EXAMPLE_ARTIST_IDS = [f"A{str(i).zfill(7)}" for i in range(1, 13)]  # A0000001-A0000012

    with app.app_context():
        Artist, Artwork, Storage, _, _, _, ArtworkPhoto = init_tables(db)

        # Count existing data (active), excluding bootstrap admin
        users_count = User.query.filter(User.role != 'admin').count()

        # Count artists excluding example data from migration
        artists_count = Artist.query.filter(
            Artist.is_deleted == False,
            ~Artist.artist_id.in_(EXAMPLE_ARTIST_IDS)
        ).count()

        # Total artists for display (including example data)
        total_artists_count = Artist.query.filter_by(is_deleted=False).count()

        artworks_count = Artwork.query.filter_by(is_deleted=False).count()
        photos_count = ArtworkPhoto.query.count()

        # Count soft-deleted data
        deleted_artists_count = Artist.query.filter_by(is_deleted=True).count()
        deleted_artworks_count = Artwork.query.filter_by(is_deleted=True).count()

        # Check for demo data
        has_demo = check_demo_data_exists(Artist, Artwork)

        # Get environment
        flask_env = os.environ.get("FLASK_ENV", "development")
        is_production = flask_env == "production"

        # Setup is required if there are no user-created artists or artworks
        # (excludes migration-seeded example artists)
        setup_required = artists_count == 0 and artworks_count == 0

        # Check if bootstrap admin is using default password
        bootstrap_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "admin@canvas-clay.local")
        bootstrap_password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe123")
        admin_user = User.query.filter_by(email=bootstrap_email.lower()).first()

        # Warn if admin exists and password env var is still default
        default_password_warning = (
            admin_user is not None and
            bootstrap_password == "ChangeMe123"
        )

        return {
            "setup_required": setup_required,
            "users_count": users_count,
            "artists_count": total_artists_count,  # Show total for display
            "user_created_artists_count": artists_count,  # Excluding example data
            "artworks_count": artworks_count,
            "photos_count": photos_count,
            "deleted_artists_count": deleted_artists_count,
            "deleted_artworks_count": deleted_artworks_count,
            "has_demo_data": has_demo,
            "environment": flask_env,
            "production_warning": is_production and setup_required,
            "default_password_warning": default_password_warning,
            "version": "1.0.0"
        }


if __name__ == "__main__":
    try:
        result = seed_demo_data()
        if result.get("skipped"):
            print("\nDemo data was already present.")
        else:
            print("\n" + "=" * 50)
            print("SECURITY REMINDERS")
            print("=" * 50)
            for warning in result["security_warnings"]:
                print(f"  - {warning}")
            print("=" * 50)
    except Exception as e:
        print(f"Error seeding demo data: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
