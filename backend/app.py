from flask import Flask, jsonify, request, send_from_directory
import os
import json
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
from auth import auth_bp, admin_required
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
                    Artwork.artwork_num.ilike(like_pattern),  # Search by artwork ID
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

        # Search photos by filename or photo ID
        photo_rows = (
            ArtworkPhoto.query.filter(
                db.or_(
                    ArtworkPhoto.filename.ilike(like_pattern),
                    ArtworkPhoto.photo_id.ilike(like_pattern)
                )
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


# Artist CRUD Endpoints
@app.route('/api/artists', methods=['GET'])
def list_artists():
    """ List all artists with pagenation, search, and filtering.
    
     Query Parameters:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20, max: 100)
        search (str): Search term (searches last name, first name, phone number)
        sort_by (str): sort by artist_id or artist_lname (artist_id default)
        sort_order (str): order by ascending or descending (ascending default)

    Returns:
        200: Paginated list of artists with full details
    """
    # Get querey parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Cap at 100
    search = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id').lower() # artist_id default
    sort_order = request.args.get('sort_order', 'asc').lower() # asdcending default

    # Build base query
    query = db.session.query(Artist)
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                Artist.artist_fname.ilike(search_pattern),
                Artist.artist_lname.ilike(search_pattern),
                Artist.artist_phone.ilike(search_pattern)
            )
        )
    
    if sort_by == 'artist_lname':
        sort_field = Artist.artist_lname
    else:
        sort_field = Artist.artist_id

    if sort_order == 'desc':
        query = query.order_by(sort_field.desc())
    else:
        query = query.order_by(sort_field.asc())
    
    # Get total count before pagination
    total = query.count()

    # Apply pagination
    query = query.offset((page - 1) * per_page).limit(per_page)

    # Execute query
    results = query.all()

    # Build response
    artists = []
    for artist in results:
        artists.append({
            'id': artist.artist_id,
            'name': f"{artist.artist_fname} {artist.artist_lname}",
            'email': artist.artist_email,
            'site': artist.artist_site,
            'bio': artist.artist_bio,
            'phone': artist.artist_phone
        })

     # Calculate pagination metadata
    total_pages = (total + per_page - 1) // per_page

    return jsonify({
        'artists': artists,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
    })
   

@app.route('/api/artists', methods=['POST'])
@login_required
@admin_required
def create_artist():
    """Create a new artist with auto-generated ID.
        
    Security:
        - Requires authentication
        - Requires admin role
        - Auto-generates artist ID
        - Audit logged
    
    Request Body: 
        artist_fname (str, required): Artist first name
        artist_lname (str, required): Artist last name
        email (str, optional): Arist email
        artist_site  (str, optional): Arist website or social media
        artist_bio   (str, optional): Artist biography/description
        artist_phone (str, optional): Artist phone number - must be formatted as 
                                                           (123)-456-7890
        user_id      (str, optional): foreign key to users table
    Returns:
        201: Artist created sucessfully
        400: Validation error
        403: Permission denied
        404: User ID not found
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    
    # Entry is missing artist_fname and/or arist_lname
    required_fields = ['artist_fname', 'artist_lname']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    
    # Verify user exists if provided
    if data.get('user_id'):
        user = Artist.query.get(data['user_id'])
        if not user:
            return jsonify({'error': f'User not found: {data["user"]}'}), 404

    # Generate artist ID
    # Find highest existing artist ID starting with 'A'
    max_id_result = db.session.query(db.func.max(Artist.artist_id)).filter(
        Artist.artist.like('A%')
    ).scalar()

    if max_id_result:
        # Extract number from A0000010 -> 10
        try:
            current_num = int(max_id_result[2:])
            new_num = current_num + 1
        except ValueError:
            new_num = 1
    else:
        new_num = 1

    # Format as A0000001
    new_artistid = f"A{new_num:07d}"

    # Handling phone number if provided, as it is a CHAR(8)
    # Format as (123)-456-7890
    artist_phone = None
    if data.get('arist_phone'):
        try:
            import re
            phone_regex = re.compile(r"^\(\d{3}\)-\d{3}-\d{4}$")
            artist_phone = str(data['artist_phone']).strip()
            if not phone_regex.match(artist_phone):
                return jsonify({'error': 'Invalid phone-number format. Expected (123)-456-7890'}), 400
        except:
            return jsonify({'error': 'Failed to validate phone-number'}), 400

    # adding artist
    try:
        artist = Artist(
            artist_id = new_artistid,
            artist_fname = data['artist_fname'],
            artist_lname = data['artist_lname'],
            artist_email = data.get('email'),
            artist_site = data.get('artist_side'),
            artist_bio = data.get('artist_bio'),
            artist_phone = artist_phone,
            user_id = data.get('user_id')
        )

        db.session.add(artist)
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artist_created',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artist_id': new_artistid,
                'artist_fname': data['artist_fname'],
                'artist_lname': data['artist_lname'],
            })
        )

        db.session.add(AuditLog)
        db.session.commit()

        app.logger.info(
            f"Admin {current_user.email} created artist {new_artistid}: "
            f"{data['artistfname']} {data['artist_lname']}")
        
        return jsonify({
            'message': 'Artist created successfully',
            'artist': {
                'id': new_artistid,
                'artist_fname': artist.artist_fname,
                'artist_lname': artist.artist_lname,
                'email': artist.artist_email,
                'artist_site': artist.artist_site,
                'artist_bio': artist.artist_bio,
                'artist_phone': artist.artist_phone,
                'user_id': artist.user_id
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artist creation failed")
        return jsonify({'error': 'Failed to create artist. Please try again.'}), 500


@app.route('/api/artists/<artist_id>', methods=['PUT'])
@login_required
@admin_required
def update_artist(artist_id):
    """Update an existing artist

    Security:
        - Requires authentication
        - Requires admin role
        - Audit logged

    Args:
        artist_id: The ID of artist to update

    Request Body: 
        artist_fname (str, required): Artist first name
        artist_lname (str, required): Artist last name
        email (str, optional): Arist email
        artist_site  (str, optional): Arist website or social media
        artist_bio   (str, optional): Artist biography/description
        artist_phone (str, optional): Artist phone number - must be formatted as 
                                                           (123)-456-7890
        user_id      (str, optional): foriegn key to user table
    
    Returns:
        200: Artist updated successfully
        400: Validation error
        403: Permission denied
        404: Artist not found
    """
    # Verify artists exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    # Track changes for audit log
    changes = {}

    # Update artist first name
    if 'artist_fname' in data and data['artist_fname'] != artist.artist_fname:
        changes['artist_fname'] = {'old': artist.artist_fname, 'new': data['artist_fname']}
        artist.artist_fname = data['artist_fname']
    
    # Update artist last name
    if 'artist_lname' in data and data['artist_lname'] != artist.artist_lname:
        changes['artist_lname'] = {'old': artist.artist_lname, 'new': data['artist_lname']}
        artist.artist_lname = data['artist_lname']
    
    # Update artist email
    if 'email' in data and data['email'] != artist.artist_email:
        changes['email'] = {'old': artist.artist_email, 'new': data['email']}
        artist.artist_email = data['email']

    # Update artist site
    if 'artist_site' in data and data['artist_site'] != artist.artist_site:
        changes['artist_site'] = {'old': artist.artist_site, 'new': data['artist_site']}
        artist.artist_site = data['artist_site']
    
    # Update artist bio
    if 'artist_bio' in data and data['artist_bio'] != artist.artist_bio:
        changes['artist_bio'] = {'old': artist.artist_bio, 'new': data['artist_bio']}
        artist.artist_bio = data['artist_bio']
    
    # Update artist phone
    if 'arist_phone' in data:
        try:
            import re
            phone_regex = re.compile(r"^\(\d{3}\)-\d{3}-\d{4}$")
            new_phone = str(data['artist_phone']).strip()
            if not phone_regex.match(new_phone):
                return jsonify({'error': 'Invalid phone-number format. Expected (123)-456-7890'}), 400
           
            if new_phone != artist.artist_phone:
                changes['artist_phone'] = {
                    'old': artist.artist_phone,
                    'new': new_phone
                }
                artist.artist_phone = new_phone
        except:
            return jsonify({'error': 'Failed to validate phone-number'}), 400
        
    # Update user id
    if 'user_id' in data and data['user_id'] != artist.user_id:
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'error': f'User ID not found: {data["user_id"]}'}), 404
        changes['user_id'] = {'old': artist.user_id, 'new': data['user_id']}
        artist.user_id = data['user_id']
    
    # If no changes, return early
    if not changes:
        return jsonify({'message': 'No changes detected', 'artist': {'id': artist_id}}), 200

    try:
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artist_updated',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artist_id': artist_id,
                'changes': changes
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} updated artist {artist_id}")

        return jsonify({
            'message': 'Artist updated successfully',
            'artist': {
                'artist_id': artist.artist_id,
                'artist_fname': artist.artist_fname,
                'artist_lname': artist.artist_lname,
                'email': artist.artist_email,
                'artist_site': artist.artist_site,
                'artist_bio': artist.artist_bio,
                'artist_phone': artist.artist_phone,
                'user_id': artist.user_id
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artist update failed")
        return jsonify({'error': 'Failed to update artist. Please try again.'}), 500


# TODO(artist CRUD, MK): Add a SOFT deletion for artist
# will have to alter the db schema in order to do so
@app.route('/api/artists/<artist_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_artist(artist_id):
    """ Delete an artist 
        - will only delete artists with no associated artwork dependencies
    
    Security:
    - Requires authentication
    - Requires admin role
    - Cascades deletion to artworks and subsequentially photos
    - Audit logged
    
    Args:
    - artist_id: the artist to delete
    
    Returns:
        200: Artists deleted successfully
        400: Artist is unable to be deleted due to existing artworks
        403: Permission denied
        404: Artist not found
    """
    # verify artist exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404
    
    # verify no data dependencies (will adjust this to soft delete after adjusting schema)
    artworks = Artwork.query.filter_by(artist_id=artist_id, is_deleted=False).count()
    if artworks > 0:
        return jsonify({
            'error': f'Cannot delete artist {artist_id}: {artworks} artworks still exist. '
                     'Please delete or reassign artworks first.'
        }), 400
    
    try:
        # Delete Artist
        artist_name = f"{artist.artist_fname} {artist.artist_lname}"
        artist_id = artist.artist_id
        db.session.delete(artist)
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artist_deleted',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artist_id': artist_id,
                'artist_name': artist_name
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} deleted artist {artist_id}")

        return jsonify({
            'message': 'Artist deleted successfully',
            'deleted': {
                'artist_id': artist_id,
                'artist_name': artist_name,
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artist deletion failed")
        return jsonify({'error': 'Failed to delete artist. Please try again.'}), 500


# Artwork CRUD Endpoints
@app.route('/api/artworks', methods=['GET'])
def list_artworks():
    """List all artworks with pagination, search, and filtering.

    Query Parameters:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20, max: 100)
        search (str): Search term (searches title, medium, artist name)
        artist_id (str): Filter by artist ID
        medium (str): Filter by medium

    Returns:
        200: Paginated list of artworks with full details
    """
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Cap at 100
    search = request.args.get('search', '').strip()
    artist_id = request.args.get('artist_id', '').strip()
    medium = request.args.get('medium', '').strip()

    # Build base query
    query = db.session.query(Artwork, Artist).join(
        Artist, Artwork.artist_id == Artist.artist_id
    )

    # Apply filters
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                Artwork.artwork_ttl.ilike(search_pattern),
                Artwork.artwork_medium.ilike(search_pattern),
                Artist.artist_fname.ilike(search_pattern),
                Artist.artist_lname.ilike(search_pattern)
            )
        )

    if artist_id:
        query = query.filter(Artwork.artist_id == artist_id)

    if medium:
        query = query.filter(Artwork.artwork_medium.ilike(f"%{medium}%"))

    # Get total count before pagination
    total = query.count()

    # Apply pagination
    query = query.order_by(Artwork.artwork_num.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    # Execute query
    results = query.all()

    # Build response
    artworks = []
    for artwork, artist in results:
        # Get primary photo or first photo
        primary_photo = ArtworkPhoto.query.filter_by(
            artwork_num=artwork.artwork_num,
            is_primary=True
        ).first()

        if not primary_photo:
            primary_photo = ArtworkPhoto.query.filter_by(
                artwork_num=artwork.artwork_num
            ).first()

        # Get photo count
        photo_count = ArtworkPhoto.query.filter_by(
            artwork_num=artwork.artwork_num
        ).count()

        # Get storage info
        storage = Storage.query.get(artwork.storage_id) if artwork.storage_id else None

        artworks.append({
            'id': artwork.artwork_num,
            'title': artwork.artwork_ttl,
            'medium': artwork.artwork_medium,
            'size': artwork.artwork_size,
            'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
            'artist': {
                'id': artist.artist_id,
                'name': f"{artist.artist_fname} {artist.artist_lname}",
                'email': artist.artist_email
            },
            'storage': {
                'id': storage.storage_id,
                'location': storage.storage_loc,
                'type': storage.storage_type
            } if storage else None,
            'primary_photo': {
                'id': primary_photo.photo_id,
                'thumbnail_url': f"/uploads/thumbnails/{os.path.basename(primary_photo.thumbnail_path)}"
            } if primary_photo else None,
            'photo_count': photo_count
        })

    # Calculate pagination metadata
    total_pages = (total + per_page - 1) // per_page

    return jsonify({
        'artworks': artworks,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
    })


@app.route('/api/artworks', methods=['POST'])
@login_required
@admin_required
def create_artwork():
    """Create a new artwork with auto-generated ID.

    Security:
        - Requires authentication
        - Requires admin role
        - Validates artist and storage exist
        - Auto-generates artwork ID
        - Audit logged

    Request Body:
        title (str, required): Artwork title
        artist_id (str, required): Artist ID (must exist)
        storage_id (str, required): Storage location ID (must exist)
        medium (str, optional): Medium/type of artwork
        date_created (str, optional): Creation date (ISO format)
        artwork_size (str, optional): Dimensions

    Returns:
        201: Artwork created successfully
        400: Validation error
        403: Permission denied
        404: Artist or storage not found
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    # Validate required fields
    required_fields = ['title', 'artist_id', 'storage_id']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Verify artist exists
    artist = Artist.query.get(data['artist_id'])
    if not artist:
        return jsonify({'error': f'Artist not found: {data["artist_id"]}'}), 404

    # Verify storage exists
    storage = Storage.query.get(data['storage_id'])
    if not storage:
        return jsonify({'error': f'Storage location not found: {data["storage_id"]}'}), 404

    # Generate new artwork ID
    # Find the highest existing artwork ID starting with 'AW'
    max_id_result = db.session.query(db.func.max(Artwork.artwork_num)).filter(
        Artwork.artwork_num.like('AW%')
    ).scalar()

    if max_id_result:
        # Extract number from AW000010 -> 10
        try:
            current_num = int(max_id_result[2:])
            new_num = current_num + 1
        except ValueError:
            new_num = 1
    else:
        new_num = 1

    # Format as AW000001
    new_artwork_id = f"AW{new_num:06d}"

    # Handle date_created if provided
    date_created = None
    if data.get('date_created'):
        try:
            from datetime import datetime
            date_created = datetime.fromisoformat(data['date_created'].replace('Z', '+00:00')).date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use ISO format (YYYY-MM-DD)'}), 400

    # Create artwork
    try:
        artwork = Artwork(
            artwork_num=new_artwork_id,
            artwork_ttl=data['title'],
            artwork_medium=data.get('medium'),
            date_created=date_created,
            artwork_size=data.get('artwork_size'),
            artist_id=data['artist_id'],
            storage_id=data['storage_id']
        )

        db.session.add(artwork)
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artwork_created',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artwork_id': new_artwork_id,
                'title': data['title'],
                'artist_id': data['artist_id'],
                'artist_name': f"{artist.artist_fname} {artist.artist_lname}",
                'storage_id': data['storage_id']
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} created artwork {new_artwork_id}: {data['title']}")

        return jsonify({
            'message': 'Artwork created successfully',
            'artwork': {
                'id': new_artwork_id,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'size': artwork.artwork_size,
                'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
                'artist_id': artwork.artist_id,
                'storage_id': artwork.storage_id
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artwork creation failed")
        return jsonify({'error': 'Failed to create artwork. Please try again.'}), 500


@app.route('/api/artworks/<artwork_id>', methods=['PUT'])
@login_required
@admin_required
def update_artwork(artwork_id):
    """Update an existing artwork.

    Security:
        - Requires authentication
        - Requires admin role
        - Validates artist and storage exist if updated
        - Audit logged

    Args:
        artwork_id: The artwork ID to update

    Request Body:
        title (str, optional): Artwork title
        artist_id (str, optional): Artist ID (must exist)
        storage_id (str, optional): Storage location ID (must exist)
        medium (str, optional): Medium/type of artwork
        date_created (str, optional): Creation date (ISO format)
        artwork_size (str, optional): Dimensions

    Returns:
        200: Artwork updated successfully
        400: Validation error
        403: Permission denied
        404: Artwork, artist, or storage not found
    """
    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    # Track changes for audit log
    changes = {}

    # Update title
    if 'title' in data and data['title'] != artwork.artwork_ttl:
        changes['title'] = {'old': artwork.artwork_ttl, 'new': data['title']}
        artwork.artwork_ttl = data['title']

    # Update artist
    if 'artist_id' in data and data['artist_id'] != artwork.artist_id:
        artist = Artist.query.get(data['artist_id'])
        if not artist:
            return jsonify({'error': f'Artist not found: {data["artist_id"]}'}), 404
        changes['artist_id'] = {'old': artwork.artist_id, 'new': data['artist_id']}
        artwork.artist_id = data['artist_id']

    # Update storage
    if 'storage_id' in data and data['storage_id'] != artwork.storage_id:
        storage = Storage.query.get(data['storage_id'])
        if not storage:
            return jsonify({'error': f'Storage location not found: {data["storage_id"]}'}), 404
        changes['storage_id'] = {'old': artwork.storage_id, 'new': data['storage_id']}
        artwork.storage_id = data['storage_id']

    # Update medium
    if 'medium' in data and data['medium'] != artwork.artwork_medium:
        changes['medium'] = {'old': artwork.artwork_medium, 'new': data['medium']}
        artwork.artwork_medium = data['medium']

    # Update size
    if 'artwork_size' in data and data['artwork_size'] != artwork.artwork_size:
        changes['artwork_size'] = {'old': artwork.artwork_size, 'new': data['artwork_size']}
        artwork.artwork_size = data['artwork_size']

    # Update date_created
    if 'date_created' in data:
        try:
            from datetime import datetime
            new_date = datetime.fromisoformat(data['date_created'].replace('Z', '+00:00')).date() if data['date_created'] else None
            if new_date != artwork.date_created:
                changes['date_created'] = {
                    'old': artwork.date_created.isoformat() if artwork.date_created else None,
                    'new': new_date.isoformat() if new_date else None
                }
                artwork.date_created = new_date
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use ISO format (YYYY-MM-DD)'}), 400

    # If no changes, return early
    if not changes:
        return jsonify({'message': 'No changes detected', 'artwork': {'id': artwork_id}}), 200

    # Save changes
    try:
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artwork_updated',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artwork_id': artwork_id,
                'changes': changes
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} updated artwork {artwork_id}")

        return jsonify({
            'message': 'Artwork updated successfully',
            'artwork': {
                'id': artwork.artwork_num,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'size': artwork.artwork_size,
                'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
                'artist_id': artwork.artist_id,
                'storage_id': artwork.storage_id
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artwork update failed")
        return jsonify({'error': 'Failed to update artwork. Please try again.'}), 500


@app.route('/api/artworks/<artwork_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_artwork(artwork_id):
    """Delete an artwork and all associated photos.

    Security:
        - Requires authentication
        - Requires admin role
        - Cascades deletion to photos (DB records and files)
        - Audit logged

    Args:
        artwork_id: The artwork ID to delete

    Returns:
        200: Artwork deleted successfully
        403: Permission denied
        404: Artwork not found
    """
    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Get all photos for audit log and file deletion
    photos = ArtworkPhoto.query.filter_by(artwork_num=artwork_id).all()
    photo_count = len(photos)

    try:
        # Delete photo files from filesystem
        for photo in photos:
            try:
                delete_photo_files(photo.file_path, photo.thumbnail_path)
            except Exception as e:
                app.logger.warning(f"Failed to delete photo files for {photo.photo_id}: {e}")

        # Delete photo database records
        ArtworkPhoto.query.filter_by(artwork_num=artwork_id).delete()

        # Delete artwork
        artwork_title = artwork.artwork_ttl
        artist_id = artwork.artist_id
        db.session.delete(artwork)
        db.session.commit()

        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='artwork_deleted',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artwork_id': artwork_id,
                'title': artwork_title,
                'artist_id': artist_id,
                'photos_deleted': photo_count
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} deleted artwork {artwork_id} with {photo_count} photos")

        return jsonify({
            'message': 'Artwork deleted successfully',
            'deleted': {
                'artwork_id': artwork_id,
                'title': artwork_title,
                'photos_deleted': photo_count
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artwork deletion failed")
        return jsonify({'error': 'Failed to delete artwork. Please try again.'}), 500


# Photo Upload Endpoints
from upload_utils import process_upload, FileValidationError, delete_photo_files, sanitize_filename
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
    if not current_user.is_admin:
        # Get the artist associated with this artwork
        artist = Artist.query.get(artwork.artist_id)
        if not artist:
            return jsonify({'error': 'Artist not found for this artwork'}), 404

        # If artist has no user_id, fall back to admin-only access (secure default)
        if not artist.user_id:
            return jsonify({
                'error': 'This artwork is not linked to a user account. Only admins can upload photos. Please contact an administrator.'
            }), 403

        # Check if current user owns this artist
        if artist.user_id != current_user.id:
            return jsonify({
                'error': 'You do not have permission to upload photos for this artwork'
            }), 403

    # Get uploaded file
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo file provided'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Read file data
    file_data = file.read()

    # Check for duplicate filename
    sanitized_name = sanitize_filename(file.filename)
    existing_photo = ArtworkPhoto.query.filter_by(filename=sanitized_name).first()
    if existing_photo:
        return jsonify({
            'error': f'A photo with the filename "{sanitized_name}" already exists (Photo ID: {existing_photo.photo_id})'
        }), 409  # 409 Conflict

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
@admin_required
@limiter.limit("20 per minute")
def upload_orphaned_photo():
    """Upload a photo without associating it to an artwork (orphaned).

    This is useful for uploading photos before creating the artwork record.
    Photos can be associated later when creating/updating artwork.

    Security:
        - Requires authentication
        - Requires admin role (prevents storage abuse by regular users)
        - Validates file type using magic bytes
        - Sanitizes filename
        - Validates file size (max 10MB)
        - Re-encodes image to strip metadata
        - Generates thumbnail
        - Rate limited to 20 per minute per IP

    Returns:
        201: Photo uploaded successfully
        400: Validation error
        403: Permission denied (non-admin)
    """
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo file provided'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_data = file.read()

    # Check for duplicate filename
    sanitized_name = sanitize_filename(file.filename)
    existing_photo = ArtworkPhoto.query.filter_by(filename=sanitized_name).first()
    if existing_photo:
        return jsonify({
            'error': f'A photo with the filename "{sanitized_name}" already exists (Photo ID: {existing_photo.photo_id})'
        }), 409  # 409 Conflict

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


@app.route('/api/photos/<photo_id>/associate', methods=['PATCH'])
@login_required
@admin_required
def associate_photo_with_artwork(photo_id):
    """Associate an orphaned photo with an artwork.

    This endpoint allows admins to link previously uploaded orphaned photos
    to specific artworks. This completes the bulk upload workflow.

    Security:
        - Requires authentication
        - Requires admin role
        - Photo must be orphaned (artwork_num=NULL)
        - Target artwork must exist
        - Audit logged for accountability

    Args:
        photo_id: The photo ID to associate

    Request Body:
        artwork_id: The artwork ID to associate the photo with

    Returns:
        200: Photo associated successfully
        400: Invalid request or photo already associated
        403: Permission denied (non-admin)
        404: Photo or artwork not found
    """
    data = request.get_json()
    if not data or 'artwork_id' not in data:
        return jsonify({'error': 'artwork_id is required'}), 400

    artwork_id = data.get('artwork_id')

    # Verify photo exists
    photo = ArtworkPhoto.query.filter_by(photo_id=photo_id).first()
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    # Check if photo is already associated with an artwork
    if photo.artwork_num is not None:
        return jsonify({
            'error': f'Photo is already associated with artwork {photo.artwork_num}'
        }), 400

    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Associate photo with artwork
    photo.artwork_num = artwork_id
    db.session.commit()

    # Audit log the association
    audit_log = AuditLog(
        user_id=current_user.id,
        email=current_user.email,
        event_type='photo_associated',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details=json.dumps({
            'photo_id': photo_id,
            'filename': photo.filename,
            'artwork_id': artwork_id,
            'artwork_title': artwork.artwork_ttl
        })
    )
    db.session.add(audit_log)
    db.session.commit()

    app.logger.info(f"Admin {current_user.email} associated photo {photo_id} with artwork {artwork_id}")

    return jsonify({
        'message': 'Photo associated successfully',
        'photo': {
            'id': photo.photo_id,
            'filename': photo.filename,
            'artwork_id': artwork_id,
            'artwork_title': artwork.artwork_ttl
        }
    }), 200


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


# Admin Management Endpoints

@app.route('/api/admin/artists/<artist_id>/assign-user', methods=['POST'])
@login_required
@admin_required
def assign_artist_to_user(artist_id):
    """Admin endpoint to link an artist to a user account.

    This enables ownership enforcement for artwork photo uploads.
    Only admins can assign artists to users.

    Security:
        - Requires authentication
        - Requires admin role

    Args:
        artist_id: The artist ID to link

    Request Body:
        user_id: The user ID to link to this artist

    Returns:
        200: Artist linked successfully
        400: Invalid request
        403: Permission denied
        404: Artist or user not found
    """
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify({'error': 'user_id is required'}), 400

    user_id = data.get('user_id')

    # Verify artist exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Verify user exists
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Link artist to user
    artist.user_id = user_id
    db.session.commit()

    return jsonify({
        'message': f'Artist {artist_id} successfully linked to user {user.email}',
        'artist': {
            'id': artist.artist_id,
            'name': f"{artist.artist_fname} {artist.artist_lname}",
            'email': artist.artist_email
        },
        'user': {
            'id': user.id,
            'email': user.email
        }
    })


@app.route('/api/admin/artists/<artist_id>/unassign-user', methods=['POST'])
@login_required
@admin_required
def unassign_artist_from_user(artist_id):
    """Admin endpoint to unlink an artist from their user account.

    This reverts to admin-only photo uploads for this artist's artworks.
    Only admins can unassign artists from users.

    Security:
        - Requires authentication
        - Requires admin role

    Args:
        artist_id: The artist ID to unlink

    Returns:
        200: Artist unlinked successfully
        403: Permission denied
        404: Artist not found
    """
    # Verify artist exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Unlink artist from user
    old_user_id = artist.user_id
    artist.user_id = None
    db.session.commit()

    return jsonify({
        'message': f'Artist {artist_id} successfully unlinked from user account',
        'artist': {
            'id': artist.artist_id,
            'name': f"{artist.artist_fname} {artist.artist_lname}",
            'previous_user_id': old_user_id
        }
    })


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

# Lazy bootstrap initialization to avoid race conditions during container startup
@app.before_request
def _ensure_bootstrap_on_first_request():
    """Lazily initialize bootstrap admin on first request.

    This runs AFTER migrations complete, avoiding race conditions
    during container startup when flask commands import app.py.
    """
    if app.config.get('TESTING', False):
        return  # Skip in test mode

    if hasattr(app, '_bootstrap_complete'):
        return  # Already bootstrapped

    try:
        # Check if users table exists before querying
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        if 'users' not in inspector.get_table_names():
            return  # Tables don't exist yet, migrations haven't run

        # Safe to bootstrap now
        ensure_bootstrap_admin()
        validate_security_config()
        app._bootstrap_complete = True

    except Exception as e:
        app.logger.warning(f"Bootstrap initialization skipped: {e}")
        # Don't set _bootstrap_complete, will retry on next request

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
