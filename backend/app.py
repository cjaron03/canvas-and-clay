from flask import Flask, jsonify, request, send_from_directory
import os
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)

# CORS configuration - move to environment variable for production
# supports multiple origins separated by commas (e.g., "http://localhost:5173,https://example.com")
cors_origins_env = os.getenv('CORS_ORIGINS', 'http://localhost:5173')
cors_origins = [origin.strip() for origin in cors_origins_env.split(',') if origin.strip()]

CORS(app, 
     origins=cors_origins,
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-CSRFToken"],
     expose_headers=["Content-Type", "X-CSRFToken"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Basic configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session security configuration
# security: default to secure=true (HTTPS only), require explicit opt-out for local dev
# set ALLOW_INSECURE_COOKIES=true in local dev environment only
allow_insecure_cookies = os.getenv('ALLOW_INSECURE_COOKIES', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = not allow_insecure_cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Remember-Me configuration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = not allow_insecure_cookies

# CSRF protection configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # token doesn't expire (session-based)
app.config['WTF_CSRF_SSL_STRICT'] = not allow_insecure_cookies
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
# accept csrf token from header (for API requests) and form field (traditional forms)
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.session_protection = 'strong'

# Initialize rate limiter
# rate limiting can be disabled via limiter.enabled = False in tests
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # use in-memory storage (can be upgraded to Redis in production)
)

# Return 401 instead of redirect for unauthorized API requests
@login_manager.unauthorized_handler
def unauthorized():
    """Return 401 for unauthorized API requests instead of redirecting."""
    return jsonify({'error': 'Authentication required'}), 401


# Initialize models
from models import init_models
User, FailedLoginAttempt, AuditLog = init_models(db)

# Initialize db tables
from create_tbls import init_tables
Artist, Artwork, Storage, FlatFile, WallSpace, Rack, ArtworkPhoto = init_tables(db)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))

# Register blueprints
from auth import auth_bp
app.register_blueprint(auth_bp)

# Security Headers - Protect against common web vulnerabilities
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Control referrer information
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    # Restrict browser features and APIs
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Additional security headers
    # XSS Protection (legacy, but helps older browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response


# TODO(security): Add rate limiting to prevent brute force attacks (Flask-Limiter)
# TODO(security): Implement CSRF protection for state-changing operations (Flask-WTF)
# TODO(security): Add input validation middleware for all endpoints

@app.route('/')
def home():
    return jsonify({
        'message': 'Welcome to Canvas and Clay API',
        'status': 'running'
    })

@app.route('/health')
def health():
    """Health check endpoint that verifies database connection
    
    Returns:
        - 200 OK: Service is healthy and database is connected
        - 503 Service Unavailable: Database connection failed
    """
    try:
        # Try to execute a simple query to check DB connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'connected'
        status = 'healthy'
        http_status = 200
    except Exception as e:
        db_status = f'error: {str(e)}'
        status = 'degraded'
        http_status = 503
    
    return jsonify({
        'status': status,
        'service': 'canvas-clay-backend',
        'database': db_status
    }), http_status

@app.route('/api/hello')
def api_hello():
    """Simple API endpoint that returns a greeting"""
    return jsonify({
        'message': 'Hello from Canvas and Clay!',
        'endpoint': '/api/hello',
        'method': 'GET'
    })


@app.route('/api/search')
def api_search():
    """Search across artworks, artists, and locations."""
    raw_query = request.args.get('q', '', type=str)
    query = raw_query.strip()

    if not query:
        return jsonify({
            'query': raw_query,
            'items': []
        })

    like_pattern = f"%{query}%"
    items = []

    try:
        # Search artworks
        artwork_rows = (
            db.session.query(Artwork, Artist, Storage)
            .join(Artist, Artwork.artist_id == Artist.artist_id)
            .outerjoin(Storage, Artwork.storage_id == Storage.storage_id)
            .filter(
                db.or_(
                    Artwork.artwork_ttl.ilike(like_pattern),
                    Artwork.artwork_medium.ilike(like_pattern),
                    Artist.artist_fname.ilike(like_pattern),
                    Artist.artist_lname.ilike(like_pattern),
                    Storage.storage_loc.ilike(like_pattern)
                )
            )
            .order_by(Artwork.artwork_ttl.asc())
            .limit(10)
            .all()
        )

        for artwork, artist, storage in artwork_rows:
            artist_name = " ".join(
                part for part in [artist.artist_fname, artist.artist_lname] if part
            ).strip() or artist.artist_fname or artist.artist_lname

            location_payload = None
            if storage:
                location_payload = {
                    'type': storage.storage_type,
                    'id': storage.storage_id,
                    'name': storage.storage_loc,
                    'profile_url': f"/locations/{storage.storage_id}"
                }

            # Get primary photo or first photo for this artwork
            primary_photo = ArtworkPhoto.query.filter_by(
                artwork_num=artwork.artwork_num,
                is_primary=True
            ).first()

            if not primary_photo:
                # Fall back to most recent photo
                primary_photo = ArtworkPhoto.query.filter_by(
                    artwork_num=artwork.artwork_num
                ).order_by(ArtworkPhoto.uploaded_at.desc()).first()

            thumbnail_url = None
            if primary_photo:
                thumbnail_url = f"/uploads/thumbnails/{os.path.basename(primary_photo.thumbnail_path)}"

            items.append({
                'type': 'artwork',
                'id': artwork.artwork_num,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'thumbnail': thumbnail_url,
                'artist': {
                    'id': artist.artist_id,
                    'name': artist_name,
                    'profile_url': f"/artists/{artist.artist_id}"
                },
                'location': location_payload,
                'profile_url': f"/artworks/{artwork.artwork_num}"
            })

        # Search artists
        artist_rows = (
            Artist.query.filter(
                db.or_(
                    Artist.artist_fname.ilike(like_pattern),
                    Artist.artist_lname.ilike(like_pattern),
                    Artist.artist_email.ilike(like_pattern),
                    Artist.artist_site.ilike(like_pattern)
                )
            )
            .order_by(Artist.artist_fname.asc(), Artist.artist_lname.asc())
            .limit(10)
            .all()
        )

        for artist in artist_rows:
            artist_name = " ".join(
                part for part in [artist.artist_fname, artist.artist_lname] if part
            ).strip() or artist.artist_fname or artist.artist_lname

            items.append({
                'type': 'artist',
                'id': artist.artist_id,
                'name': artist_name,
                'email': artist.artist_email,
                'site': artist.artist_site,
                'profile_url': f"/artists/{artist.artist_id}"
            })

        # Search locations
        storage_rows = (
            Storage.query.filter(
                db.or_(
                    Storage.storage_loc.ilike(like_pattern),
                    Storage.storage_type.ilike(like_pattern),
                    Storage.storage_id.ilike(like_pattern)
                )
            )
            .order_by(Storage.storage_loc.asc())
            .limit(10)
            .all()
        )

        for storage in storage_rows:
            items.append({
                'type': 'location',
                'id': storage.storage_id,
                'name': storage.storage_loc,
                'storage_type': storage.storage_type,
                'profile_url': f"/locations/{storage.storage_id}"
            })

        # Search photos by filename
        photo_rows = (
            ArtworkPhoto.query.filter(
                ArtworkPhoto.filename.ilike(like_pattern)
            )
            .order_by(ArtworkPhoto.uploaded_at.desc())
            .limit(10)
            .all()
        )

        for photo in photo_rows:
            photo_item = {
                'type': 'photo',
                'id': photo.photo_id,
                'filename': photo.filename,
                'thumbnail': f"/uploads/thumbnails/{os.path.basename(photo.thumbnail_path)}",
                'url': f"/uploads/artworks/{os.path.basename(photo.file_path)}",
                'width': photo.width,
                'height': photo.height,
                'file_size': photo.file_size,
                'uploaded_at': photo.uploaded_at.isoformat(),
                'is_primary': photo.is_primary
            }

            # If photo is associated with an artwork, include artwork info
            if photo.artwork_num:
                artwork = Artwork.query.get(photo.artwork_num)
                if artwork:
                    photo_item['artwork'] = {
                        'id': artwork.artwork_num,
                        'title': artwork.artwork_ttl,
                        'profile_url': f"/artworks/{artwork.artwork_num}"
                    }
            else:
                # Orphaned photo - not associated with any artwork
                photo_item['orphaned'] = True

            items.append(photo_item)

    except Exception as exc:
        app.logger.exception("Search failed for query '%s'", query)
        return jsonify({
            'query': raw_query,
            'items': [],
            'error': 'Search failed. Please try again later.'
        }), 500

    return jsonify({
        'query': raw_query,
        'items': items
    })


# Photo Upload Endpoints
from upload_utils import process_upload, FileValidationError, delete_photo_files
from auth import admin_required


@app.route('/api/artworks/<artwork_id>/photos', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def upload_artwork_photo(artwork_id):
    """Upload a photo for an existing artwork.

    Security:
        - Requires authentication
        - User must own the artwork OR be admin
        - Validates file type using magic bytes
        - Sanitizes filename
        - Validates file size (max 10MB)
        - Re-encodes image to strip metadata
        - Generates thumbnail

    Args:
        artwork_id: The artwork ID to attach the photo to

    Request:
        - multipart/form-data with 'photo' file field
        - Optional 'is_primary' boolean field

    Returns:
        201: Photo uploaded successfully with metadata
        400: Validation error
        403: Permission denied
        404: Artwork not found
    """
    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Check permissions (admin or artwork owner)
    # For now, allow any authenticated user - can add ownership check later
    if not current_user.is_admin:
        # TODO: Add ownership check when we have artist-user relationships
        pass

    # Get uploaded file
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo file provided'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Read file data
    file_data = file.read()

    try:
        # Process upload with full security validation
        photo_metadata = process_upload(file_data, file.filename)

        # Check if this should be the primary photo
        is_primary = request.form.get('is_primary', 'false').lower() == 'true'

        # If setting as primary, unset other primary photos for this artwork
        if is_primary:
            ArtworkPhoto.query.filter_by(
                artwork_num=artwork_id,
                is_primary=True
            ).update({'is_primary': False})

        # Create database record
        photo = ArtworkPhoto(
            photo_id=photo_metadata['photo_id'],
            artwork_num=artwork_id,
            filename=photo_metadata['filename'],
            file_path=photo_metadata['file_path'],
            thumbnail_path=photo_metadata['thumbnail_path'],
            file_size=photo_metadata['file_size'],
            mime_type=photo_metadata['mime_type'],
            width=photo_metadata['width'],
            height=photo_metadata['height'],
            uploaded_at=datetime.now(timezone.utc),
            uploaded_by=current_user.id,
            is_primary=is_primary
        )

        db.session.add(photo)
        db.session.commit()

        return jsonify({
            'message': 'Photo uploaded successfully',
            'photo': {
                'id': photo.photo_id,
                'filename': photo.filename,
                'url': f"/uploads/artworks/{os.path.basename(photo.file_path)}",
                'thumbnail_url': f"/uploads/thumbnails/{os.path.basename(photo.thumbnail_path)}",
                'width': photo.width,
                'height': photo.height,
                'file_size': photo.file_size,
                'is_primary': photo.is_primary
            }
        }), 201

    except FileValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception("Photo upload failed")
        return jsonify({'error': 'Upload failed. Please try again.'}), 500


@app.route('/api/photos', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def upload_orphaned_photo():
    """Upload a photo without associating it to an artwork (orphaned).

    This is useful for uploading photos before creating the artwork record.
    Photos can be associated later when creating/updating artwork.

    Security: Same as upload_artwork_photo

    Returns:
        201: Photo uploaded successfully
        400: Validation error
    """
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo file provided'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_data = file.read()

    try:
        photo_metadata = process_upload(file_data, file.filename)

        # Create orphaned photo record (artwork_num is NULL)
        photo = ArtworkPhoto(
            photo_id=photo_metadata['photo_id'],
            artwork_num=None,  # Orphaned
            filename=photo_metadata['filename'],
            file_path=photo_metadata['file_path'],
            thumbnail_path=photo_metadata['thumbnail_path'],
            file_size=photo_metadata['file_size'],
            mime_type=photo_metadata['mime_type'],
            width=photo_metadata['width'],
            height=photo_metadata['height'],
            uploaded_at=datetime.now(timezone.utc),
            uploaded_by=current_user.id,
            is_primary=False
        )

        db.session.add(photo)
        db.session.commit()

        return jsonify({
            'message': 'Photo uploaded successfully',
            'photo': {
                'id': photo.photo_id,
                'filename': photo.filename,
                'url': f"/uploads/artworks/{os.path.basename(photo.file_path)}",
                'thumbnail_url': f"/uploads/thumbnails/{os.path.basename(photo.thumbnail_path)}",
                'width': photo.width,
                'height': photo.height,
                'file_size': photo.file_size
            }
        }), 201

    except FileValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception("Photo upload failed")
        return jsonify({'error': 'Upload failed. Please try again.'}), 500


@app.route('/api/artworks/<artwork_id>/photos', methods=['GET'])
def get_artwork_photos(artwork_id):
    """Get all photos for an artwork.

    Args:
        artwork_id: The artwork ID

    Returns:
        200: List of photos
        404: Artwork not found
    """
    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Get all photos for this artwork
    photos = ArtworkPhoto.query.filter_by(artwork_num=artwork_id).order_by(
        ArtworkPhoto.is_primary.desc(),
        ArtworkPhoto.uploaded_at.desc()
    ).all()

    return jsonify({
        'artwork_id': artwork_id,
        'photos': [{
            'id': photo.photo_id,
            'filename': photo.filename,
            'url': f"/uploads/artworks/{os.path.basename(photo.file_path)}",
            'thumbnail_url': f"/uploads/thumbnails/{os.path.basename(photo.thumbnail_path)}",
            'width': photo.width,
            'height': photo.height,
            'file_size': photo.file_size,
            'is_primary': photo.is_primary,
            'uploaded_at': photo.uploaded_at.isoformat()
        } for photo in photos]
    })


@app.route('/api/photos/<photo_id>', methods=['DELETE'])
@login_required
@limiter.limit("20 per minute")
def delete_photo(photo_id):
    """Delete a photo.

    Security:
        - Requires authentication
        - User must own the photo OR be admin

    Args:
        photo_id: The photo ID to delete

    Returns:
        200: Photo deleted successfully
        403: Permission denied
        404: Photo not found
    """
    photo = ArtworkPhoto.query.get(photo_id)
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    # Check permissions
    if not current_user.is_admin and photo.uploaded_by != current_user.id:
        return jsonify({'error': 'Permission denied'}), 403

    # Delete files from filesystem
    delete_photo_files(photo.file_path, photo.thumbnail_path)

    # Delete database record
    db.session.delete(photo)
    db.session.commit()

    return jsonify({'message': 'Photo deleted successfully'})


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files securely.

    Security:
        - Prevents directory traversal (send_from_directory handles this)
        - Only serves files from uploads directory
        - Sets proper Content-Type headers

    Args:
        filename: Path to the file (e.g., "artworks/photo.jpg" or "thumbnails/thumb.jpg")

    Returns:
        File contents or 404
    """
    try:
        # Additional security check for path traversal attempts
        if '..' in filename or filename.startswith('/'):
            return jsonify({'error': 'Invalid file path'}), 400

        # Construct full path to uploads directory
        upload_dir = os.path.join(os.path.dirname(__file__), 'uploads')

        # send_from_directory already prevents directory traversal
        return send_from_directory(upload_dir, filename)

    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404


# TODO(security, JC): Implement JWT token authentication for API endpoints (optional)

def ensure_bootstrap_admin():
    """ensure the bootstrap admin user exists and has admin role.
    
    this function should be called on application startup to guarantee
    at least one admin user exists in the system.
    """
    bootstrap_email = os.getenv('BOOTSTRAP_ADMIN_EMAIL', 'admin@canvas-clay.local').strip().lower()
    
    if not bootstrap_email:
        return
    
    try:
        with app.app_context():
            user = User.query.filter_by(email=bootstrap_email).first()
            
            if user:
                # ensure existing bootstrap admin has admin role
                if user.role != 'admin':
                    user.role = 'admin'
                    db.session.commit()
                    print(f"promoted {bootstrap_email} to admin role")
            else:
                # bootstrap admin doesn't exist - create with default password
                # admin should change this on first login
                default_password = os.getenv('BOOTSTRAP_ADMIN_PASSWORD', 'ChangeMe123')
                hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
                
                admin_user = User(
                    email=bootstrap_email,
                    hashed_password=hashed_password,
                    role='admin',
                    created_at=datetime.now(timezone.utc)
                )
                
                db.session.add(admin_user)
                db.session.commit()
                print(f"created bootstrap admin: {bootstrap_email}")
                print("warning: default password in use - change immediately!")
    except Exception as e:
        # silently fail if database isn't ready yet (e.g., during migrations)
        # this is expected during initial setup
        pass

# startup validation - warn about insecure configuration
def validate_security_config():
    """validate security configuration and warn about potential issues."""
    if app.config.get('TESTING', False):
        return
    
    # warn if insecure cookies are allowed (should only be in local dev)
    if allow_insecure_cookies:
        print("warning: ALLOW_INSECURE_COOKIES is enabled - cookies will be sent over HTTP")
        print("warning: this should only be used in local development, not in production")
    
    # warn if CORS origins include localhost (may indicate dev config in production)
    localhost_origins = [origin for origin in cors_origins if 'localhost' in origin.lower()]
    if localhost_origins and not allow_insecure_cookies:
        print(f"warning: CORS origins include localhost: {localhost_origins}")
        print("warning: ensure CORS_ORIGINS is configured correctly for production")

# ensure bootstrap admin exists on startup (skip in test mode)
if not app.config.get('TESTING', False):
    ensure_bootstrap_admin()
    validate_security_config()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
