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
        db.session.rollback()
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


@setup_bp.route('/bulk-delete', methods=['POST'])
@login_required
def bulk_delete():
    """Bulk delete artworks with soft or hard delete option.

    Requires admin authentication. Deletes specified number of artworks
    or all artworks based on request parameters.

    Request JSON:
        count: int or "all" - number of items to delete
        delete_type: "soft" or "hard" - soft marks as deleted, hard removes permanently
        include_artists: bool - also delete associated artists
        include_photos: bool - also delete associated photos (default true for hard delete)

    Returns:
        JSON: {success: bool, deleted: {artworks, artists, photos}}
    """
    db, User, init_tables, admin_required = get_dependencies()

    # Check admin role
    if current_user.role != 'admin':
        return jsonify({
            "error": "Admin access required",
            "detail": "Only administrators can perform bulk deletions"
        }), 403

    data = request.get_json() or {}
    count = data.get('count', 5)
    delete_type = data.get('delete_type', 'soft')
    include_artists = data.get('include_artists', False)
    include_photos = data.get('include_photos', delete_type == 'hard')

    if delete_type not in ('soft', 'hard'):
        return jsonify({
            "error": "Invalid delete_type",
            "detail": "Must be 'soft' or 'hard'"
        }), 400

    try:
        Artist, Artwork, Storage, _, _, _, ArtworkPhoto = init_tables(db)
        from upload_utils import delete_photo_files
        from datetime import date

        deleted_counts = {
            "artworks": 0,
            "artists": 0,
            "photos": 0
        }

        # Get artworks to delete
        if count == "all":
            if delete_type == 'soft':
                artworks = Artwork.query.filter_by(is_deleted=False).all()
            else:
                artworks = Artwork.query.all()
        else:
            count = int(count)
            if delete_type == 'soft':
                artworks = Artwork.query.filter_by(is_deleted=False).limit(count).all()
            else:
                artworks = Artwork.query.limit(count).all()

        artist_ids_to_check = set()

        for artwork in artworks:
            artist_ids_to_check.add(artwork.artist_id)

            if delete_type == 'soft':
                # Soft delete - mark as deleted
                artwork.is_deleted = True
                artwork.date_deleted = date.today()
                deleted_counts["artworks"] += 1

                # Soft delete photos if requested
                if include_photos:
                    photos = ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).all()
                    for photo in photos:
                        # For soft delete, we just unlink photos (set artwork_num to NULL)
                        photo.artwork_num = None
                        deleted_counts["photos"] += 1
            else:
                # Hard delete - remove permanently
                # Delete photos first (foreign key)
                photos = ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).all()
                for photo in photos:
                    if include_photos:
                        delete_photo_files(photo.file_path, photo.thumbnail_path)
                        db.session.delete(photo)
                        deleted_counts["photos"] += 1
                    else:
                        # Orphan the photo instead of deleting
                        photo.artwork_num = None

                db.session.delete(artwork)
                deleted_counts["artworks"] += 1

        # Handle artist deletion if requested
        if include_artists:
            for artist_id in artist_ids_to_check:
                artist = db.session.get(Artist, artist_id)
                if not artist:
                    continue

                # Check if artist has remaining artworks
                remaining = Artwork.query.filter_by(artist_id=artist_id)
                if delete_type == 'soft':
                    remaining = remaining.filter_by(is_deleted=False)
                remaining_count = remaining.count()

                if remaining_count == 0:
                    if delete_type == 'soft':
                        artist.is_deleted = True
                        artist.date_deleted = date.today()
                    else:
                        db.session.delete(artist)
                    deleted_counts["artists"] += 1

        db.session.commit()

        return jsonify({
            "success": True,
            "deleted": deleted_counts,
            "delete_type": delete_type
        }), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to perform bulk delete",
            "detail": str(e)
        }), 500


@setup_bp.route('/restore-deleted', methods=['POST'])
@login_required
def restore_deleted():
    """Restore soft-deleted artworks.

    Requires admin authentication. Restores specified number of
    soft-deleted artworks.

    Request JSON:
        count: int or "all" - number of items to restore

    Returns:
        JSON: {success: bool, restored: {artworks, artists}}
    """
    db, User, init_tables, admin_required = get_dependencies()

    # Check admin role
    if current_user.role != 'admin':
        return jsonify({
            "error": "Admin access required",
            "detail": "Only administrators can restore deletions"
        }), 403

    data = request.get_json() or {}
    count = data.get('count', 'all')

    try:
        Artist, Artwork, Storage, _, _, _, ArtworkPhoto = init_tables(db)

        restored_counts = {
            "artworks": 0,
            "artists": 0
        }

        # Get soft-deleted artworks
        if count == "all":
            artworks = Artwork.query.filter_by(is_deleted=True).all()
        else:
            count = int(count)
            artworks = Artwork.query.filter_by(is_deleted=True).limit(count).all()

        artist_ids_to_check = set()

        for artwork in artworks:
            artist_ids_to_check.add(artwork.artist_id)
            artwork.is_deleted = False
            artwork.date_deleted = None
            restored_counts["artworks"] += 1

        # Restore associated artists if they were soft-deleted
        for artist_id in artist_ids_to_check:
            artist = db.session.get(Artist, artist_id)
            if artist and artist.is_deleted:
                artist.is_deleted = False
                artist.date_deleted = None
                restored_counts["artists"] += 1

        db.session.commit()

        return jsonify({
            "success": True,
            "restored": restored_counts
        }), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to restore deleted items",
            "detail": str(e)
        }), 500
