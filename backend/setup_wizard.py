"""Setup wizard API blueprint for Canvas & Clay.

Provides endpoints for checking setup status and seeding demo data.
Used by the frontend setup wizard to initialize new installations.
"""
import os
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user


setup_bp = Blueprint('setup', __name__, url_prefix='/api/setup')


def get_dependencies():
    """Get dependencies from app context to avoid circular imports."""
    from app import db, User
    from create_tbls import init_tables
    from auth import admin_required
    return db, User, init_tables, admin_required


@setup_bp.route('/status', methods=['GET'])
def get_setup_status():
    """Get current setup status.

    Returns setup state information without requiring authentication.
    Used by the frontend to determine if setup wizard should be shown.

    Returns:
        JSON: {
            setup_required: bool,
            users_count: int,
            artists_count: int,
            artworks_count: int,
            has_demo_data: bool,
            environment: str,
            production_warning: bool,
            version: str
        }
    """
    from seed_demo import check_setup_status
    try:
        status = check_setup_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({
            "error": "Failed to check setup status",
            "detail": str(e)
        }), 500


@setup_bp.route('/seed-demo-data', methods=['POST'])
@login_required
def seed_demo_data():
    """Seed demo data for new installations.

    Requires admin authentication. Creates demo users, artists,
    artworks, and placeholder images.

    Returns:
        JSON: {
            success: bool,
            created: {users, artists, artworks, photos},
            security_warnings: [str]
        }
    """
    db, User, init_tables, admin_required = get_dependencies()

    # Check admin role
    if current_user.role != 'admin':
        return jsonify({
            "error": "Admin access required",
            "detail": "Only administrators can seed demo data"
        }), 403

    # Check environment and warn if production
    flask_env = os.environ.get("FLASK_ENV", "development")
    if flask_env == "production":
        # Check for confirmation header
        confirm = request.headers.get('X-Confirm-Production', 'false')
        if confirm.lower() != 'true':
            return jsonify({
                "error": "Production environment detected",
                "detail": "Set X-Confirm-Production: true header to proceed",
                "environment": flask_env
            }), 400

    from seed_demo import seed_demo_data as do_seed
    try:
        result = do_seed()
        return jsonify(result), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to seed demo data",
            "detail": str(e)
        }), 500


@setup_bp.route('/clear-demo-data', methods=['DELETE'])
@login_required
def clear_demo_data():
    """Remove demo data from the database.

    Requires admin authentication. Removes demo users, artists,
    artworks, and their associated photos.

    Returns:
        JSON: {success: bool, removed: {users, artists, artworks, photos}}
    """
    db, User, init_tables, admin_required = get_dependencies()

    # Check admin role
    if current_user.role != 'admin':
        return jsonify({
            "error": "Admin access required",
            "detail": "Only administrators can clear demo data"
        }), 403

    try:
        Artist, Artwork, Storage, _, _, _, ArtworkPhoto = init_tables(db)
        from upload_utils import delete_photo_files
        from seed_demo import DEMO_ARTIST_ID, DEMO_STORAGE_ID, DEMO_USERS, DEMO_ARTWORKS

        removed_counts = {
            "users": 0,
            "artists": 0,
            "artworks": 0,
            "photos": 0
        }

        # Remove demo photos first (foreign key constraint)
        demo_artwork_nums = [aw["artwork_num"] for aw in DEMO_ARTWORKS]
        photos = ArtworkPhoto.query.filter(
            ArtworkPhoto.artwork_num.in_(demo_artwork_nums)
        ).all()
        for photo in photos:
            delete_photo_files(photo.file_path, photo.thumbnail_path)
            db.session.delete(photo)
            removed_counts["photos"] += 1

        # Remove demo artworks
        for artwork_num in demo_artwork_nums:
            artwork = db.session.get(Artwork, artwork_num)
            if artwork:
                db.session.delete(artwork)
                removed_counts["artworks"] += 1

        # Remove demo artist
        artist = db.session.get(Artist, DEMO_ARTIST_ID)
        if artist:
            db.session.delete(artist)
            removed_counts["artists"] += 1

        # Remove demo storage
        storage = db.session.get(Storage, DEMO_STORAGE_ID)
        if storage:
            db.session.delete(storage)

        # Remove demo users (but not admin)
        for user_data in DEMO_USERS:
            user = User.query.filter_by(email=user_data["email"].lower()).first()
            if user and user.role != 'admin':
                db.session.delete(user)
                removed_counts["users"] += 1

        db.session.commit()

        return jsonify({
            "success": True,
            "removed": removed_counts
        }), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to clear demo data",
            "detail": str(e)
        }), 500
