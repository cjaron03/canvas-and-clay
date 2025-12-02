from flask import Flask, jsonify, request, send_from_directory, session
import os
import json
import secrets
import string
import sys
from datetime import timedelta, datetime, timezone, date
from urllib.parse import quote_plus
from functools import wraps
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import sanitize_html

load_dotenv()

# Check if we're running in a test environment
def is_test_environment():
    """Check if we're running in a test environment (pytest, CI, etc.)"""
    # Check for pytest environment variable (set by pytest)
    if os.getenv('PYTEST_CURRENT_TEST') is not None:
        return True
    # Check for CI environment (GitHub Actions, etc.)
    if os.getenv('CI') is not None:
        return True
    # Check if pytest is in sys.modules (pytest has been imported)
    if 'pytest' in sys.modules:
        return True
    # Check if pytest is in the command line
    if len(sys.argv) > 0 and 'pytest' in sys.argv[0]:
        return True
    return False


def get_env_int(name, default):
    """Safely parse integer environment variables with defaults."""
    value = os.getenv(name)
    if value is None or value == '':
        return default
    try:
        return int(value)
    except ValueError:
        return default


def build_database_uri():
    """Construct database URI from environment variables."""
    # Prefer explicit test database when running under pytest/CI
    test_db_uri = os.getenv('TEST_DATABASE_URL') or os.getenv('PYTEST_DATABASE_URL')
    if os.getenv('PYTEST_CURRENT_TEST') and test_db_uri:
        return test_db_uri
    if os.getenv('PYTEST_CURRENT_TEST') and not os.getenv('DATABASE_URL') and not test_db_uri:
        # Safe default for tests when no DB is configured
        return 'sqlite:///app_test.db'

    existing_uri = os.getenv('DATABASE_URL')
    if existing_uri:
        return existing_uri

    db_name = os.getenv('DB_NAME')
    db_host = os.getenv('DB_HOST')

    # Fall back to sqlite for local dev if not fully configured
    if not db_name or not db_host:
        return 'sqlite:///app.db'

    db_port = os.getenv('DB_PORT', '5432')
    db_engine = os.getenv('DB_ENGINE', 'postgresql')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')

    auth = ''
    if db_user:
        auth = quote_plus(db_user)
        if db_password:
            auth += f":{quote_plus(db_password)}"
        auth += '@'

    host_part = f"{db_host}:{db_port}" if db_port else db_host
    return f"{db_engine}://{auth}{host_part}/{db_name}"


def build_engine_options(database_uri):
    """Configure SQLAlchemy engine options such as pooling and SSL."""
    # SQLite (default/testing) uses NullPool; skip pool configuration
    if database_uri.startswith('sqlite'):
        return {}

    engine_options = {
        'pool_size': get_env_int('DB_POOL_SIZE', 5),
        'max_overflow': get_env_int('DB_POOL_MAX_OVERFLOW', 10),
        'pool_timeout': get_env_int('DB_POOL_TIMEOUT', 30),
        'pool_recycle': get_env_int('DB_POOL_RECYCLE', 1800),
        'pool_pre_ping': os.getenv('DB_POOL_PRE_PING', 'true').lower() == 'true',
    }

    ssl_mode = os.getenv('DB_SSL_MODE')
    if ssl_mode and database_uri.startswith('postgresql'):
        connect_args = {'sslmode': ssl_mode}
        ssl_root_cert = os.getenv('DB_SSL_ROOT_CERT')
        if ssl_root_cert:
            connect_args['sslrootcert'] = ssl_root_cert
        engine_options['connect_args'] = connect_args

    return engine_options

allow_insecure_cookies = os.getenv('ALLOW_INSECURE_COOKIES', 'False').lower() == 'true'
PASSWORD_RESET_CODE_TTL_MINUTES = get_env_int('PASSWORD_RESET_CODE_TTL_MINUTES', 15)
MAX_PASSWORD_RESET_MESSAGE_LENGTH = get_env_int('PASSWORD_RESET_MESSAGE_MAX_LENGTH', 500)

app = Flask(__name__)

# CORS configuration - move to environment variable for production
# supports multiple origins separated by commas (e.g., "http://localhost:5173,https://example.com")
cors_origins_env = os.getenv('CORS_ORIGINS')
# Only allow the localhost default when explicitly using insecure cookies (local dev) or in tests
if not cors_origins_env:
    if not allow_insecure_cookies and not is_test_environment():
        raise RuntimeError("CORS_ORIGINS must be set when running with secure cookies")
    cors_origins_env = 'http://localhost:5173'
cors_origins = [origin.strip() for origin in cors_origins_env.split(',') if origin.strip()]

CORS(app, 
     origins=cors_origins,
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-CSRFToken"],
     expose_headers=["Content-Type", "X-CSRFToken"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Basic configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
database_uri = build_database_uri()
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
engine_options = build_engine_options(database_uri)
if engine_options:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session security configuration
# security: default to secure=true (HTTPS only), require explicit opt-out for local dev
# set ALLOW_INSECURE_COOKIES=true in local dev environment only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = not allow_insecure_cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Remember-Me configuration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = not allow_insecure_cookies
app.config['PASSWORD_RESET_CODE_TTL_MINUTES'] = PASSWORD_RESET_CODE_TTL_MINUTES
app.config['PASSWORD_RESET_MESSAGE_MAX_LENGTH'] = MAX_PASSWORD_RESET_MESSAGE_LENGTH

# CSRF protection configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # token doesn't expire (session-based)
app.config['WTF_CSRF_SSL_STRICT'] = not allow_insecure_cookies
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
# accept csrf token from header (for API requests) and form field (traditional forms)
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']

# Fail fast when running with secure cookies but SECRET_KEY is not set
if not allow_insecure_cookies and app.config['SECRET_KEY'] == 'dev-secret-key-change-in-production' and not is_test_environment():
    raise RuntimeError("SECRET_KEY must be set in the environment for non-development environments")

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.session_protection = 'strong'

# Custom key function factory - will be called after User model is defined
def create_rate_limit_key_func():
    """Create rate limit key function that exempts admin users from rate limiting.
    
    Returns None for admin users (which disables rate limiting),
    otherwise returns the remote address for IP-based limiting.
    
    Note: This runs before route decorators, so we manually check the session
    to load the user if they're authenticated.
    """
    def rate_limit_key_func():
        try:
            # First try current_user (might be loaded by Flask-Login already)
            if current_user.is_authenticated and hasattr(current_user, 'is_admin') and current_user.is_admin:
                return None  # None disables rate limiting for this request
        except Exception:
            pass
        
        # If current_user isn't available, manually check session
        # Flask-Login stores user ID in session['_user_id'] or session['_id']
        try:
            from flask import has_request_context
            if not has_request_context():
                return get_remote_address()
            
            # Check all possible Flask-Login session keys
            # Flask-Login uses '_user_id' by default, but check other possibilities
            user_id = session.get('_user_id') or session.get('_id') or session.get('user_id')
            
            if user_id:
                # Access User model (captured in closure after it's defined)
                # User is available at runtime since this function is created after init_models
                try:
                    user = db.session.get(User, int(user_id)) if user_id else None
                    if user:
                        if hasattr(user, 'is_admin') and user.is_admin:
                            return None  # None disables rate limiting for this request
                except (NameError, AttributeError, ValueError) as e:
                    # User model not available or invalid user_id
                    pass
        except Exception as e:
            # If there's any error checking user, fall back to IP-based limiting
            pass
        
        return get_remote_address()
    
    return rate_limit_key_func

# Initialize rate limiter with a placeholder - will be updated after User is defined
# We'll create the actual key function after User model is initialized
limiter = None  # Will be initialized after User model is available


def get_rate_limit_by_identity():
    """Get rate limit based on user identity type.

    Rate limits:
        - Anonymous (no session): 100 requests/minute
        - Logged-in guest: 200 requests/minute
        - Admin: 1000 requests/minute

    Returns:
        String rate limit for Flask-Limiter
    """
    try:
        if current_user.is_authenticated:
            if current_user.is_admin:
                return "1000 per minute"
            else:
                # Logged-in guest (includes artist-linked users)
                return "200 per minute"
        else:
            # Anonymous user
            return "100 per minute"
    except Exception:
        # Fallback to anonymous rate limit if anything fails
        return "100 per minute"


def dynamic_rate_limit():
    """Decorator factory for dynamic rate limiting based on user identity."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        # Apply the rate limit dynamically
        return limiter.limit(get_rate_limit_by_identity)(wrapper)
    return decorator

# Return 401 instead of redirect for unauthorized API requests
@login_manager.unauthorized_handler
def unauthorized():
    """Return 401 for unauthorized API requests instead of redirecting."""
    return jsonify({'error': 'Authentication required'}), 401


# Initialize models
from models import init_models
User, FailedLoginAttempt, AuditLog = init_models(db)
PasswordResetRequest = init_models.PasswordResetRequest

# Canonical bootstrap admin email used for safeguard checks
BOOTSTRAP_ADMIN_EMAIL = (os.getenv('BOOTSTRAP_ADMIN_EMAIL') or 'admin@canvas-clay.local').strip().lower()

# Now initialize rate limiter with key function that can access User model
rate_limit_key_func = create_rate_limit_key_func()
limiter = Limiter(
    app=app,
    key_func=rate_limit_key_func,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # use in-memory storage (can be upgraded to Redis in production)
)

# Initialize db tables
from create_tbls import init_tables
Artist, Artwork, Storage, FlatFile, WallSpace, Rack, ArtworkPhoto = init_tables(db)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return db.session.get(User, int(user_id))

# Enforce per-session token to allow forced logouts
@app.before_request
def enforce_session_token():
    try:
        if not current_user.is_authenticated:
            return
        token = session.get('session_token')
        if not token or token != current_user.remember_token:
            logout_user()
            session.clear()
            return jsonify({'error': 'Session expired. Please log in again.'}), 401
    except Exception:
        # On any unexpected error, fail closed by clearing session
        logout_user()
        session.clear()
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

# Register blueprints
from auth import auth_bp, admin_required, is_artwork_owner, is_photo_owner, log_rbac_denial, log_audit_event
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
    
    # Content-Security-Policy - prevent XSS attacks
    # strict policy for JSON API: only allow resources from same origin
    csp_policy = os.getenv('CSP_POLICY', (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ))
    response.headers['Content-Security-Policy'] = csp_policy
    
    return response


# TODO(security): Add rate limiting to prevent brute force attacks (Flask-Limiter)
# TODO(security): Implement CSRF protection for state-changing operations (Flask-WTF)
# TODO(security): Add input validation middleware for all endpoints

@app.route('/')
@limiter.limit("60 per minute")  # Allow frequent health checks for admin console
def home():
    # TEMPORARY: Breaking API for testing health check
    # Uncomment the line below to break the API for testing
    # raise Exception("API intentionally broken for testing")
    
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
        app.logger.exception("Health check database probe failed")
        db_status = 'error'
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
@limiter.limit(get_rate_limit_by_identity)  # Dynamic limit based on user identity
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
                artwork = db.session.get(Artwork, photo.artwork_num)
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
def list_artists_page():
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
    sort_by = request.args.get('sort_by', 'artist_id').lower() # artist_id default
    sort_order = request.args.get('sort_order', 'asc').lower() # asdcending default
    
    # Build base query, filter out deleted artists
    query = db.session.query(Artist).filter(Artist.is_deleted==False)
    
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
        email        (str, optional): Artist email
        artist_site  (str, optional): Artist website or social media
        artist_bio   (str, optional): Artist biography/description
        artist_phone (str, optional): Artist phone number - must be formatted as 
                                                           (123)-456-7890
        is_deleted   (bool, required): Deletion status -  always set to false 
                                                        (only changed in deletion)
        date_deleted (date, optional):  date of deletion - will be set to none
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
    
    # Entry is missing artist_fname and/or artist_lname
    required_fields = ['artist_fname', 'artist_lname']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    
    # Verify user exists if provided
    if data.get('user_id'):
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'error': f'User not found: {data["user_id"]}'}), 404
        
    # Generate new artist ID using cryptographically secure random generation
    def generate_random_artist_id():
        """Generate a random artist ID in format A#######"""
        max_attempts = 100
        for _ in range(max_attempts):
            random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(7))
            artist_id = f"A{random_part}"
            if not Artist.query.get(artist_id):
                return artist_id
        raise ValueError("Failed to generate unique artwork ID after max attempts")
    
    new_artistid = generate_random_artist_id()

    # Handling phone number if provided, as it is a CHAR(8)
    # Format as (123)-456-7890
    artist_phone = None
    if data.get('artist_phone'):
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
            artist_site = data.get('artist_site'),
            artist_bio = data.get('artist_bio'),
            artist_phone = artist_phone,
            is_deleted = False,
            date_deleted = None,
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

        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(
            f"Admin {current_user.email} created artist {new_artistid}: "
            f"{data['artist_fname']} {data['artist_lname']}")
        
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
                'is_deleted': artist.is_deleted,
                'date_deleted': artist.date_deleted,
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
        email (str, optional): Artist email
        artist_site  (str, optional): Artist website or social media
        artist_bio   (str, optional): Artist biography/description
        artist_phone (str, optional): Artist phone number - must be formatted as 
                                                           (123)-456-7890
        user_id      (str, optional): foriegn key to user table
    
    Returns:
        200: Artist updated successfully or no changes
        400: Validation error
        403: Permission denied
        404: Artist not found, or artist is deleted
    """
    # Verify artists exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404
    
    # Verify artist is not deleted
    if artist.is_deleted:
        return jsonify({'error': 'Artist is deleted.'}), 404

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
    if 'artist_phone' in data:
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
        except Exception as e:
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


# need to add directory in front end /api/artists/[id]/restore
@app.route('/api/artists/<artist_id>/restore', methods=['PUT'])
@login_required
@admin_required
def restore_deleted_artist(artist_id):
    """ Restores a SOFT deleted artist
        - hard deletions will not be able to be restored
        - will change date_deleted back to None
    Security:
        - Requires authentication
        - Requires admin role
        - Audit logged
    Args:
        - artwist_id: The artist ID to be restored

    Returns:
        200: Artist restored successfully
        403: Permisison denied
        404: Artist not found, artist is not deleted
    """
    # Verify artwork exists
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404
    
    # Verify artwork is currently deleted
    if not artist.is_deleted:
        return jsonify({'error': 'Artist is not deleted'}), 404
    
    try:
        # restoring soft deleted artwork
        artist.is_deleted = False
        artist.date_deleted = None

        artist_name = f"{artist.artist_fname} {artist.artist_lname}"
        artist_id = artist.artist_id

        is_deleted = artist.is_deleted
        date_deleted = artist.date_deleted

        db.session.commit()

        # audit restoration
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='deleted_artist_restored',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artist_name': artist_name,
                'artist_id': artist_id,
                'is_deleted': is_deleted,
                'date_deleted': date_deleted
            })
        )

        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} restored artwork {artist_id}")

        return jsonify({
            'message': 'Deleted artist restored successfully',
            'restored': {
                'artist_id': artist_id,
                'artist_name': artist_name,
                'is_deleted': is_deleted,
                'date_deleted': date_deleted
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Deleted Artist restoration failed")
        return jsonify({'error': 'Failed to restore deleted artist. Please try again'}), 500



@app.route('/api/artists/<artist_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_artist(artist_id):
    """ Delete an artist 
        - will only delete artists with no associated artwork dependencies
           (as in, all artworks have been soft-deleted)
        - if not marked as deleted, will change is_deleted to true and mark the date
          of deletion
        - if is_deleted is already set to true, it will hard delete it
    Security:
    - Requires authentication
    - Requires admin role
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
    artwork_count = Artwork.query.filter_by(artist_id=artist_id, is_deleted=False).count()
    if artwork_count > 0:
        return jsonify({
            'error': f'Cannot delete artist {artist_id}: {artwork_count} artworks still exist. '
                     'Please delete or reassign artworks first.'
        }), 400
    
    try:
        # Grab deletion status
        artist_name = f"{artist.artist_fname} {artist.artist_lname}"
        deletion_date = date.today()
        deletion_type = None
        artworks = Artwork.query.filter_by(artist_id=artist.artist_id).all()
        total_artworks = len(artworks)
        total_photos = 0

        # Hard deletion (if is_deleted is already set to True)
        if artist.is_deleted:
            
            # Deleting data dependencies
            for artwork in artworks:
                # Grab photos associated with artwork
                photos = ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).all()
                total_photos += len(photos)

                for photo in photos:
                    try:
                        delete_photo_files(photo.file_path, photo.thumbnail_path)
                    except Exception as e:
                        app.logger.warning(f"Failed to delete photo files for {photo.photo_id}: {e}")
               
                # Delete photo from ArtworkPhoto
                ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).delete() 

                # Delete artwork
                db.session.delete(artwork)
            
            # Delete artist
            db.session.delete(artist)
            deletion_type = "Hard-deleted"
        # Soft deletion (if artist has not been deleted before)
        else:

            # Grabbing number of photos for logging purposes
            for artwork in artworks:
                photos = ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).all()
                total_photos += len(photos)

            artist.is_deleted = True
            artist.date_deleted = deletion_date
            deletion_type = "Soft-deleted"

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
                'artist_name': artist_name,
                'deletion_type': deletion_type,
                'date_deleted': deletion_date.isoformat(),
                'total_artworks': total_artworks,
                'total_photos': total_photos
            })
        )
        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} {deletion_type} artist {artist_id} ({artist_name}) "
                        f"with {total_artworks} artworks and {total_photos} photos.")

        return jsonify({
            'message': 'Artist deleted successfully',
            'deleted': {
                'artist_id': artist_id,
                'artist_name': artist_name,
                'deletion_type': deletion_type,
                'date_deleted': deletion_date.isoformat(),
                'total_artworks': total_artworks,
                'total_photos': total_photos
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artist deletion failed")
        return jsonify({'error': 'Failed to delete artist. Please try again.'}), 500


# Artwork CRUD Endpoints
@app.route('/api/artworks', methods=['GET'])
@limiter.limit(get_rate_limit_by_identity)  # Dynamic limit based on user identity
def list_artworks():
    """List all artworks with pagination, search, and filtering.
       Will not show soft deleted artworks.

    Query Parameters:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20, max: 100)
        search (str): Search term (searches title, medium, artist name)
        artist_id (str): Filter by artist ID
        medium (str): Filter by medium
        storage_id (str): Filter by storage location ID

        ordering (str): Sort order for results (title_asc/title_desc, default: title_asc)

    Returns:
        200: Paginated list of artworks with full details
=======
    """
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Cap at 100
    search = request.args.get('search', '').strip()
    artist_id = request.args.get('artist_id', '').strip()
    medium = request.args.get('medium', '').strip()
    storage_id = request.args.get('storage_id', '').strip()
    ordering = request.args.get('ordering', 'title_asc').strip().lower()
    owned_only = request.args.get('owned', 'false').lower() == 'true'

    try:
        # Log all query parameters for debugging
        app.logger.info(f"list_artworks called with: owned_only={owned_only}, page={page}, per_page={per_page}, search={search}, artist_id={artist_id}")
        app.logger.info(f"current_user.is_authenticated={current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else 'N/A'}")
        
        # Build base query - use inner join when filtering by ownership to ensure artist exists
        if owned_only:
            app.logger.info(f"owned_only is True, checking authentication...")
            if not current_user.is_authenticated:
                app.logger.warning(f"owned_only=True but user not authenticated")
                return jsonify({'error': 'Authentication required'}), 401
            # For owned_only, use inner join to ensure artist exists and filter by user_id
            # This applies to both admins and regular users when they request owned artworks
            # Explicitly check that user_id is not NULL and matches current user
            # Convert both to int to ensure type matching
            current_user_id = int(current_user.id)
            query = db.session.query(Artwork, Artist).join(
                Artist, Artwork.artist_id == Artist.artist_id
            ).filter(
                Artist.user_id.isnot(None),
                Artist.user_id == current_user_id,
                Artwork.is_deleted == False
            )
            # Log for debugging
            app.logger.info(f"Filtering artworks for user_id={current_user_id}, email={current_user.email}, owned_only={owned_only}")
            # Also log what artists are assigned to this user
            assigned_artists = Artist.query.filter_by(user_id=current_user_id).all()
            app.logger.info(f"Artists assigned to user {current_user_id}: {[a.artist_id for a in assigned_artists]}")
            # Log the SQL query being generated (for debugging)
            try:
                from sqlalchemy.dialects import postgresql
                sql_str = str(query.statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
                app.logger.debug(f"Generated SQL query: {sql_str}")
            except Exception as e:
                app.logger.debug(f"Could not generate SQL string: {e}")
        else:
            # Build base query with LEFT JOIN to handle artworks without artists
            query = db.session.query(Artwork, Artist).outerjoin(
                Artist, Artwork.artist_id == Artist.artist_id
            ).filter(Artwork.is_deleted==False)

        # Apply filters
        if search:
            search_pattern = f"%{search}%"
            # Build search conditions - handle NULL artists gracefully
            search_conditions = [
                Artwork.artwork_ttl.ilike(search_pattern),
                Artwork.artwork_medium.ilike(search_pattern)
            ]
            # Add artist search conditions (will be NULL-safe with outerjoin)
            search_conditions.extend([
                Artist.artist_fname.ilike(search_pattern),
                Artist.artist_lname.ilike(search_pattern)
            ])
            query = query.filter(db.or_(*search_conditions))

        if artist_id:
            query = query.filter(Artwork.artist_id == artist_id)

        if medium:
            query = query.filter(Artwork.artwork_medium.ilike(f"%{medium}%"))
        if storage_id:
            query = query.filter(Artwork.storage_id == storage_id)

        # Get total count before pagination
        # For owned_only, log the count before pagination for debugging
        if owned_only and current_user.is_authenticated:
            app.logger.info(f"Total artworks matching ownership filter (before pagination): {query.count()}")
        total = query.count()

        # Apply alphabetical ordering w/ default ascending if no order given
        ordering_map = {
            'title_asc': Artwork.artwork_ttl.asc(),
            'title_desc': Artwork.artwork_ttl.desc()
        }
        order_clause = ordering_map.get(ordering, ordering_map['title_asc'])
        query = query.order_by(order_clause)

        # Apply pagination
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query
        results = query.all()
        
        # Log query results for debugging when owned_only is true
        if owned_only and current_user.is_authenticated:
            app.logger.info(f"Query returned {len(results)} artworks for user_id={current_user.id}")
            for artwork, artist in results:
                app.logger.info(f"  - Artwork {artwork.artwork_num} (artist_id={artwork.artist_id}) -> Artist {artist.artist_id if artist else 'None'} (user_id={artist.user_id if artist else 'None'})")

        # Build response
        artworks = []
        for artwork, artist in results:
            # Double-check ownership when owned_only is true (defensive programming)
            if owned_only and current_user.is_authenticated:
                current_user_id = int(current_user.id)
                if not artist:
                    app.logger.warning(f"Skipping artwork {artwork.artwork_num}: no artist found")
                    continue
                if not artist.user_id:
                    app.logger.warning(f"Skipping artwork {artwork.artwork_num}: artist {artist.artist_id} has no user_id")
                    continue
                if int(artist.user_id) != current_user_id:
                    app.logger.warning(f"Skipping artwork {artwork.artwork_num}: artist {artist.artist_id} user_id {artist.user_id} != current_user.id {current_user_id}")
                    continue
                # Log successful match for debugging
                app.logger.info(f"Including artwork {artwork.artwork_num} from artist {artist.artist_id} (user_id={artist.user_id})")

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
            storage = db.session.get(Storage, artwork.storage_id) if artwork.storage_id else None

            # Build artist info safely
            artist_info = None
            if artist:
                artist_name = 'Unknown Artist'
                if artist.artist_fname and artist.artist_lname:
                    artist_name = f"{artist.artist_fname} {artist.artist_lname}"
                elif artist.artist_fname:
                    artist_name = artist.artist_fname
                elif artist.artist_lname:
                    artist_name = artist.artist_lname
                
                artist_info = {
                    'id': artist.artist_id,
                    'name': artist_name,
                    'email': artist.artist_email,
                    'user_id': artist.user_id
                }
            else:
                artist_info = {
                    'id': None,
                    'name': 'Unknown Artist',
                    'email': None,
                    'user_id': None
                }

            artwork_data = {
                'id': artwork.artwork_num,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'size': artwork.artwork_size,
                'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
                'artist': artist_info,
                'is_viewable': artwork.is_viewable,
                'storage': {
                    'id': storage.storage_id,
                    'location': storage.storage_loc or '',
                    'type': storage.storage_type or ''
                } if storage else None,
                'primary_photo': {
                    'id': primary_photo.photo_id,
                    'thumbnail_url': f"/uploads/thumbnails/{os.path.basename(primary_photo.thumbnail_path)}"
                } if primary_photo else None,
                'photo_count': photo_count
            }
            
            # Log each artwork being added for debugging when owned_only is true
            if owned_only and current_user.is_authenticated:
                app.logger.info(f"Adding artwork {artwork.artwork_num} (artist_id={artwork.artist_id}, artist.user_id={artist.user_id if artist else 'None'})")
            
            artworks.append(artwork_data)

        # Calculate pagination metadata
        total_pages = (total + per_page - 1) // per_page

        response_data = {
            'artworks': artworks,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        }
        
        # Add debug info when owned_only is true
        if owned_only and current_user.is_authenticated:
            response_data['_debug'] = {
                'owned_only': True,
                'user_id': int(current_user.id),
                'user_email': current_user.email,
                'artworks_count': len(artworks),
                'assigned_artists': [a.artist_id for a in Artist.query.filter_by(user_id=int(current_user.id)).all()]
            }
            app.logger.info(f"Returning {len(artworks)} artworks for user {current_user.email} (user_id={current_user.id})")
        
        return jsonify(response_data), 200
    except Exception as e:
        app.logger.exception("Failed to list artworks")
        return jsonify({'error': 'Failed to load artworks. Please try again.'}), 500


@app.route('/api/artworks/<artwork_id>', methods=['GET'])
@limiter.limit(get_rate_limit_by_identity)  # Dynamic limit based on user identity
def get_artwork(artwork_id):
    """Get detailed information about a specific artwork.

    Args:
        artwork_id: The artwork ID

    Returns:
        200: Complete artwork details
        404: Artwork not found, or artwork is deleted
    """
    # Get artwork
    artwork = db.session.get(Artwork, artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404
    
    # if artwork is deleted
    if artwork.is_deleted:
        return jsonify({'error': 'Artwork is deleted'}), 404

    # Get artist
    artist = db.session.get(Artist, artwork.artist_id)

    # Get storage
    storage = db.session.get(Storage, artwork.storage_id) if artwork.storage_id else None

    # Get all photos
    photos = ArtworkPhoto.query.filter_by(artwork_num=artwork_id).order_by(
        ArtworkPhoto.is_primary.desc(),
        ArtworkPhoto.uploaded_at.desc()
    ).all()

    return jsonify({
        'id': artwork.artwork_num,
        'title': artwork.artwork_ttl,
        'medium': artwork.artwork_medium,
        'size': artwork.artwork_size,
        'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
        'artist': {
            'id': artist.artist_id,
            'name': f"{artist.artist_fname} {artist.artist_lname}",
            'email': artist.artist_email,
            'phone': artist.artist_phone,
            'website': artist.artist_site,
            'bio': artist.artist_bio,
            'user_id': artist.user_id
        } if artist else None,
        'storage': {
            'id': storage.storage_id,
            'location': storage.storage_loc,
            'type': storage.storage_type
        } if storage else None,
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
    }), 200


@app.route('/api/artists', methods=['GET'])
def list_artists():
    """List all artists for dropdown selection.
    
    Returns:
        200: List of all artists with id and name
    """
    try:
        artists = Artist.query.filter(Artist.is_deleted==False).order_by(Artist.artist_fname, Artist.artist_lname).all()
        return jsonify({
            'artists': [
                {
                    'id': artist.artist_id,
                    'name': f"{artist.artist_fname} {artist.artist_lname}".strip(),
                    'user_id': artist.user_id
                }
                for artist in artists
            ]
        }), 200
    except Exception as e:
        app.logger.exception("Failed to list artists")
        return jsonify({'error': 'Failed to load artists'}), 500


@app.route('/api/storage', methods=['GET'])
def list_storage():
    """List all storage locations for dropdown selection.
    
    Returns:
        200: List of all storage locations with id, location, and type
    """
    try:
        storage_locations = Storage.query.order_by(Storage.storage_loc).all()
        return jsonify({
            'storage': [
                {
                    'id': storage.storage_id,
                    'location': storage.storage_loc or '',
                    'type': storage.storage_type or ''
                }
                for storage in storage_locations
            ]
        }), 200
    except Exception as e:
        app.logger.exception("Failed to list storage locations")
        return jsonify({'error': 'Failed to load storage locations'}), 500


@app.route('/api/artworks', methods=['POST'])
@login_required
def create_artwork():
    """Create a new artwork with auto-generated ID.

    Security:
        - Requires authentication
        - Requires admin role OR artist role with ownership of the linked artist
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
        404: Artist or storage not found, or artist deleted
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
    artist = db.session.get(Artist, data['artist_id'])
    if not artist:
        return jsonify({'error': f'Artist not found: {data["artist_id"]}'}), 404

   
    # Authorization: admins can create any; artists can create only for their linked artist record
    if not current_user.is_admin:
        if current_user.normalized_role != 'artist':
            log_rbac_denial('artwork', 'create', 'insufficient_role')
            return jsonify({'error': 'Permission denied'}), 403
        if not artist.user_id or str(artist.user_id) != str(current_user.id):
            log_rbac_denial('artwork', 'create', 'not_owner')
            return jsonify({'error': 'You can only create artworks for your own artist profile'}), 403

    # Verify artist is not deleted
    if artist.is_deleted:
        return jsonify({'error': f'Artist is deleted: {data["artist_id"]}'}), 404
    
    # Verify storage exists
    storage = db.session.get(Storage, data['storage_id'])
    if not storage:
        return jsonify({'error': f'Storage location not found: {data["storage_id"]}'}), 404

    # Generate new artwork ID using cryptographically secure random generation
    def generate_random_artwork_id():
        """Generate a random artwork ID in format AW######"""
        max_attempts = 100
        for _ in range(max_attempts):
            random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            artwork_id = f"AW{random_part}"
            if not db.session.get(Artwork, artwork_id):
                return artwork_id
        raise ValueError("Failed to generate unique artwork ID after max attempts")
    
    new_artwork_id = generate_random_artwork_id()

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
            is_viewable=True,
            is_deleted=False,
            date_deleted=None,
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

        app.logger.info(f"User {current_user.email} created artwork {new_artwork_id}: {data['title']}")

        return jsonify({
            'message': 'Artwork created successfully',
            'artwork': {
                'id': new_artwork_id,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'size': artwork.artwork_size,
                'date_created': artwork.date_created.isoformat() if artwork.date_created else None,
                'is_viewable': artwork.is_viewable,
                'is_deleted': artwork.is_deleted,
                'date_deleted': artwork.date_deleted.isoformat() if artwork.date_deleted else None,
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
def update_artwork(artwork_id):
    """Update an existing artwork.

    Security:
        - Requires authentication
        - Requires admin role OR artwork ownership
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
        404: Artwork, artist, or storage not found, or artist deleted
    """
    # Verify artwork exists
    artwork = db.session.get(Artwork, artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404
    
    # Verify artwork is not deleted
    if artwork.is_deleted:
        return jsonify({'error': 'Artwork is deleted'}), 404

    # Check permissions: admin or artwork owner
    if not current_user.is_admin and not is_artwork_owner(artwork):
        log_rbac_denial('artwork', artwork_id, 'not_owner')
        return jsonify({'error': 'Permission denied'}), 403

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
        artist = db.session.get(Artist, data['artist_id'])
        if not artist:
            return jsonify({'error': f'Artist not found: {data["artist_id"]}'}), 404
        
        # Verify artist is not deleted
        if artist.is_deleted:
            return jsonify({'error': f'Artist is deleted: {data["artist_id"]}'}), 404
        changes['artist_id'] = {'old': artwork.artist_id, 'new': data['artist_id']}
        artwork.artist_id = data['artist_id']

    # Update storage
    if 'storage_id' in data and data['storage_id'] != artwork.storage_id:
        storage = db.session.get(Storage, data['storage_id'])
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
                'is_deleted': artwork.is_deleted,
                'date_deleted': artwork.date_deleted.isoformat() if artwork.date_deleted else None,
                'artist_id': artwork.artist_id,
                'storage_id': artwork.storage_id
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Artwork update failed")
        return jsonify({'error': 'Failed to update artwork. Please try again.'}), 500


# need to add directory in front end /api/artists/[id]/restore
@app.route('/api/artworks/<artwork_id>/restore', methods=['PUT'])
@login_required
@admin_required
def restore_deleted_artwork(artwork_id):
    """ Restores a SOFT deleted artwork
        - hard deletions will not be able to be restored
        - will change date_deleted back to None
    Security:
        - Requires authentication
        - Requires admin role
        - Audit logged
    Args:
        - artwork_id: The artwork ID to be restored
    Returns:
        200: Artwork restored successfully
        403: Permisison denied
        404: Artwork not found, artwork is not deleted
    """
    # Verify artwork exists
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Verify artwork is currently deleted
    if not artwork.is_deleted:
        return jsonify({'error': 'Artwork is not deleted'}), 404

    try:
        # restoring soft deleted artwork
        artwork.is_deleted = False
        artwork.date_deleted = None

        artwork_title = artwork.artwork_ttl
        artist_id = artwork.artist_id
        is_deleted = artwork.is_deleted
        date_deleted = artwork.date_deleted
        db.session.commit()

        # audit restoration
        audit_log = AuditLog(
            user_id=current_user.id,
            email=current_user.email,
            event_type='deleted_artwork_restored',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details=json.dumps({
                'artwork_id': artwork_id,
                'title': artwork_title,
                'artist_id': artist_id,
                'is_deleted': is_deleted,
                'date_deleted': date_deleted
            })
        )

        db.session.add(audit_log)
        db.session.commit()

        app.logger.info(f"Admin {current_user.email} restored artwork {artwork_id}")

        return jsonify({
            'message': 'Deleted artwork restored successfully',
            'restored': {
                'artwork_id': artwork_id,
                'title': artwork_title,
                'artist_id': artist_id,
                'is_deleted': is_deleted,
                'date_deleted': date_deleted
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Deleted Artwork restoration failed")
        return jsonify({'error': 'Failed to restore deleted artwork. Please try again'}), 500


@app.route('/api/artworks/<artwork_id>', methods=['DELETE'])
@login_required
def delete_artwork(artwork_id):
    """Delete an artwork and all associated photos.

    Security:
        - Requires authentication
        - Requires admin role OR artwork ownership
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
    artwork = db.session.get(Artwork, artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Check permissions: admin or artwork owner
    if not current_user.is_admin and not is_artwork_owner(artwork):
        log_rbac_denial('artwork', artwork_id, 'not_owner')
        return jsonify({'error': 'Permission denied'}), 403

    # Get all photos for audit log and file deletion
    photos = ArtworkPhoto.query.filter_by(artwork_num=artwork_id).all()
    photo_count = len(photos)

    try:
        deletion_type = None # specifying hard/soft delete
        deletion_date = date.today() # date of deletion
        artwork_title = artwork.artwork_ttl
        artist_id = artwork.artist_id

        # hard deletion - also deletes photos
        if artwork.is_deleted:
            # Delete photo files from filesystem
            for photo in photos:
                try:
                    delete_photo_files(photo.file_path, photo.thumbnail_path)
                except Exception as e:
                    app.logger.warning(f"Failed to delete photo files for {photo.photo_id}: {e}")

            # Delete photo database records
            ArtworkPhoto.query.filter_by(artwork_num=artwork_id).delete()

            # Delete artwork
            db.session.delete(artwork)
            deletion_type = "Hard-deleted"

        else:
            artwork.is_deleted = True
            artwork.date_deleted = deletion_date
            deletion_type = "Soft-deleted"

        # Commit artwork     
        
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
                'photos_deleted': photo_count,
                'deletion_type': deletion_type,
                'deletion_date': deletion_date.isoformat()
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
    artwork = db.session.get(Artwork, artwork_id)
    if not artwork:
        return jsonify({'error': 'Artwork not found'}), 404

    # Check permissions (admin or artwork owner)
    if not current_user.is_admin:
        # Get the artist associated with this artwork
        artist = db.session.get(Artist, artwork.artist_id)
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
    artwork = db.session.get(Artwork, artwork_id)
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
@limiter.limit(get_rate_limit_by_identity)  # Dynamic limit based on user identity
def get_artwork_photos(artwork_id):
    """Get all photos for an artwork.

    Args:
        artwork_id: The artwork ID

    Returns:
        200: List of photos
        404: Artwork not found
    """
    # Verify artwork exists
    artwork = db.session.get(Artwork, artwork_id)
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
        - User must own the artwork (via Artist.user_id) OR be admin
        - If user owns artwork, they can delete any photo on it

    Args:
        photo_id: The photo ID to delete

    Returns:
        200: Photo deleted successfully
        403: Permission denied
        404: Photo not found
    """
    photo = db.session.get(ArtworkPhoto, photo_id)
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    # Check permissions: admin OR artwork owner (can delete any photo on their artwork)
    if not current_user.is_admin and not is_photo_owner(photo):
        log_rbac_denial('photo', photo_id, 'not_owner')
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
    artist = db.session.get(Artist, artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Verify user exists
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if _is_bootstrap_admin(user):
        return jsonify({'error': 'Cannot assign an artist to the bootstrap admin account'}), 403

    # Unassign any other artists that were previously assigned to this user
    # This ensures only one artist is linked to a user at a time
    previously_assigned = Artist.query.filter_by(user_id=user_id).all()
    unassigned_count = 0
    for prev_artist in previously_assigned:
        if prev_artist.artist_id != artist_id:
            app.logger.info(f"Unassigning artist {prev_artist.artist_id} from user {user_id} (reassigning to {artist_id})")
            prev_artist.user_id = None
            unassigned_count += 1
    
    # Log if we're reassigning (artist already has this user_id)
    if artist.user_id == user_id:
        app.logger.info(f"Artist {artist_id} is already assigned to user {user_id}, but cleaning up other assignments")

    # Link artist to user
    artist.user_id = user_id
    
    # Commit all changes (unassignments + new assignment)
    db.session.commit()
    app.logger.info(f"Successfully assigned artist {artist_id} to user {user_id}, unassigned {unassigned_count} other artist(s)")

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


@app.route('/api/artists/<artist_id>/self-assign', methods=['POST'])
@login_required
def self_assign_artist(artist_id):
    """Allow an artist (or admin) to assign an artist record to their own account."""
    artist = db.session.get(Artist, artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Admins can always self-assign; artists can only claim unassigned or already owned records
    if not current_user.is_admin:
        if current_user.normalized_role != 'artist':
            return jsonify({'error': 'Permission denied'}), 403
        if artist.user_id and str(artist.user_id) != str(current_user.id):
            return jsonify({'error': 'Artist is already assigned to another user'}), 403

    artist.user_id = current_user.id
    db.session.commit()

    log_audit_event(
        'artist_user_self_assigned',
        user_id=current_user.id,
        email=current_user.email,
        details={
            'artist_id': artist_id,
            'assigned_user_id': current_user.id,
            'assigned_user_email': current_user.email
        }
    )

    return jsonify({'message': 'Artist assigned to your account', 'artist_id': artist_id}), 200


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
    artist = db.session.get(Artist, artist_id)
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


# Admin Console Endpoints
@app.route('/api/admin/console/stats', methods=['GET'])
@login_required
@admin_required
def admin_console_stats():
    """Admin console endpoint for system statistics.
    
    Returns counts and recent activity metrics.
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Statistics data
        403: Permission denied
    """
    try:
        from datetime import datetime, timezone, timedelta
        
        # Get total counts
        total_artworks = Artwork.query.count()
        total_artists = Artist.query.count()
        total_photos = ArtworkPhoto.query.count()
        total_users = User.query.count()

        # Derived role count for artist-guest users
        artist_role_count = User.query.filter(User.role.in_(['artist', 'artist-guest'])).count()
        total_storage = Storage.query.count()
        total_audit_logs = AuditLog.query.count()
        total_reset_requests = PasswordResetRequest.query.count()
        pending_reset_requests = PasswordResetRequest.query.filter(
            PasswordResetRequest.status.in_(['pending', 'approved'])
        ).count()
        
        # Get recent activity (last 24 hours)
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        
        recent_artworks = Artwork.query.filter(
            Artwork.date_created >= twenty_four_hours_ago.date()
        ).count() if hasattr(Artwork, 'date_created') else 0
        
        recent_photos = ArtworkPhoto.query.filter(
            ArtworkPhoto.uploaded_at >= twenty_four_hours_ago
        ).count()
        
        recent_users = User.query.filter(
            User.created_at >= twenty_four_hours_ago
        ).count()
        
        recent_failed_logins = FailedLoginAttempt.query.filter(
            FailedLoginAttempt.attempted_at >= twenty_four_hours_ago
        ).count()
        recent_reset_requests = PasswordResetRequest.query.filter(
            PasswordResetRequest.created_at >= twenty_four_hours_ago
        ).count()
        
        return jsonify({
            'counts': {
                'artworks': total_artworks,
                # Align admin console with role-based artist count
                'artists': artist_role_count,
                'artist_users': artist_role_count,
                'artists_db': total_artists,
                'photos': total_photos,
                'users': total_users,
                'storage_locations': total_storage,
                'audit_logs': total_audit_logs,
                'password_reset_requests': total_reset_requests,
                'password_reset_pending': pending_reset_requests
            },
            'recent_activity': {
                'artworks_last_24h': recent_artworks,
                'photos_last_24h': recent_photos,
                'users_last_24h': recent_users,
                'failed_logins_last_24h': recent_failed_logins,
                'password_resets_last_24h': recent_reset_requests
            }
        }), 200
    except Exception as e:
        app.logger.exception("Failed to fetch admin console stats")
        return jsonify({'error': 'Failed to fetch statistics'}), 500


@app.route('/api/admin/console/artists', methods=['GET'])
@login_required
@admin_required
def admin_console_artists():
    """Admin console endpoint to list artists with assignment info."""
    try:
        artists = Artist.query.order_by(Artist.artist_fname, Artist.artist_lname).all()
        artist_data = []
        for artist in artists:
            user = db.session.get(User, artist.user_id) if artist.user_id else None
            artist_data.append({
                'id': artist.artist_id,
                'name': f"{artist.artist_fname} {artist.artist_lname}".strip(),
                'email': artist.artist_email,
                'user_id': artist.user_id,
                'user_email': user.email if user else None
            })
        return jsonify({'artists': artist_data}), 200
    except Exception:
        app.logger.exception("Failed to fetch artists")
        return jsonify({'error': 'Failed to fetch artists'}), 500


@app.route('/api/stats/overview', methods=['GET'])
def public_overview_stats():
    """Public overview stats for homepage (no auth required).

    Returns total counts for artworks, artists, photos, and artist-role users.
    """
    try:
        total_artworks = Artwork.query.count()
        total_artists = Artist.query.count()
        total_photos = ArtworkPhoto.query.count()
        artist_role_count = User.query.filter(User.role.in_(['artist', 'artist-guest'])).count()

        return jsonify({
            'counts': {
                'artworks': total_artworks,
                # Homepage shows role-based artists (artist-guest users)
                'artists': artist_role_count,
                'artist_users': artist_role_count,
                'artists_db': total_artists,
                'photos': total_photos
            }
        }), 200
    except Exception:
        app.logger.exception("Failed to fetch public overview stats")
        return jsonify({'error': 'Failed to fetch statistics'}), 500


@app.route('/api/admin/console/health', methods=['GET'])
@limiter.limit("60 per minute")  # Allow frequent health checks for admin console
@login_required
@admin_required
def admin_console_health():
    """Admin console endpoint for extended health check.
    
    Returns database connection status and service information.
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Health data
        403: Permission denied
    """
    try:
        # Check database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'connected'
        status = 'healthy'
    except Exception as e:
        db_status = f'error: {str(e)}'
        status = 'degraded'
    
    # Get database engine info
    db_engine = db.engine.url.drivername if hasattr(db.engine, 'url') else 'unknown'
    
    return jsonify({
        'status': status,
        'service': 'canvas-clay-backend',
        'database': {
            'status': db_status,
            'engine': db_engine
        },
        'environment': os.getenv('FLASK_ENV', 'production')
    }), 200


@app.route('/api/admin/console/audit-log', methods=['GET'])
@login_required
@admin_required
def admin_console_audit_log():
    """Admin console endpoint for security audit logs.
    
    Query parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 50, max: 200)
        - event_type: Filter by event type (optional)
        - limit: Limit results (optional, overrides pagination)
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Paginated audit log entries
        403: Permission denied
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        event_type = request.args.get('event_type', None)
        limit = request.args.get('limit', None, type=int)

        only_alerts = request.args.get('alerts', 'false').lower() == 'true'
        
        query = AuditLog.query.order_by(AuditLog.created_at.desc())
        
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)

        if only_alerts:
            query = query.filter(AuditLog.event_type.in_([
                'alert_failed_login_spike',
                'alert_role_change_spike',
                'user_promoted',
                'user_demoted'
            ]))
        
        if limit:
            # Return limited results without pagination
            logs = query.limit(limit).all()
            return jsonify({
                'audit_logs': [
                    {
                        'id': log.id,
                        'event_type': log.event_type,
                        'user_id': log.user_id,
                        'email': log.email,
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'created_at': log.created_at.isoformat() if log.created_at else None,
                        'details': log.details
                    }
                    for log in logs
                ],
                'total': len(logs)
            }), 200
        
        # Paginated results
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'audit_logs': [
                {
                    'id': log.id,
                    'event_type': log.event_type,
                    'user_id': log.user_id,
                    'email': log.email,
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent,
                    'created_at': log.created_at.isoformat() if log.created_at else None,
                    'details': log.details
                }
                for log in pagination.items
            ],
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        }), 200
    except Exception as e:
        app.logger.exception("Failed to fetch audit logs")
        return jsonify({'error': 'Failed to fetch audit logs'}), 500


@app.route('/api/admin/console/audit-log/cleanup', methods=['POST'])
@login_required
@admin_required
def admin_console_audit_log_cleanup():
    """Cleanup audit logs older than the specified number of days.

    Request JSON:
        { "days": <int, optional, default 90> }

    If days <= 0, all audit logs are deleted.
    """
    try:
        data = request.get_json(silent=True) or {}
        days = int(data.get('days', 90))

        if days <= 0:
            deleted = AuditLog.query.delete()
        else:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            deleted = AuditLog.query.filter(AuditLog.created_at < cutoff).delete()

        db.session.commit()

        return jsonify({
            'message': f'Deleted {deleted} audit logs',
            'deleted': deleted
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to cleanup audit logs")
        return jsonify({'error': 'Failed to cleanup audit logs'}), 500


@app.route('/api/admin/console/failed-logins', methods=['GET'])
@login_required
@admin_required
def admin_console_failed_logins():
    """Admin console endpoint for failed login attempts.
    
    Query parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 50, max: 200)
        - limit: Limit results (optional, overrides pagination)
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Paginated failed login attempts
        403: Permission denied
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        limit = request.args.get('limit', None, type=int)
        
        query = FailedLoginAttempt.query.order_by(FailedLoginAttempt.attempted_at.desc())
        
        if limit:
            # Return limited results without pagination
            attempts = query.limit(limit).all()
            return jsonify({
                'failed_logins': [
                    {
                        'id': attempt.id,
                        'email': attempt.email,
                        'ip_address': attempt.ip_address,
                        'attempted_at': attempt.attempted_at.isoformat() if attempt.attempted_at else None,
                        'user_agent': attempt.user_agent
                    }
                    for attempt in attempts
                ],
                'total': len(attempts)
            }), 200
        
        # Paginated results
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'failed_logins': [
                {
                    'id': attempt.id,
                    'email': attempt.email,
                    'ip_address': attempt.ip_address,
                    'attempted_at': attempt.attempted_at.isoformat() if attempt.attempted_at else None,
                    'user_agent': attempt.user_agent
                }
                for attempt in pagination.items
            ],
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        }), 200
    except Exception as e:
        app.logger.exception("Failed to fetch failed login attempts")
        return jsonify({'error': 'Failed to fetch failed login attempts'}), 500


@app.route('/api/admin/console/failed-logins/cleanup', methods=['POST'])
@login_required
@admin_required
def admin_console_failed_logins_cleanup():
    """Cleanup failed login attempts older than the specified number of days.

    Request JSON:
        { "days": <int, optional, default 30> }

    If days <= 0, all failed login attempts are deleted.
    """
    try:
        data = request.get_json(silent=True) or {}
        days = int(data.get('days', 30))

        if days <= 0:
            deleted = FailedLoginAttempt.query.delete()
        else:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            deleted = FailedLoginAttempt.query.filter(FailedLoginAttempt.attempted_at < cutoff).delete()

        db.session.commit()

        return jsonify({
            'message': f'Deleted {deleted} failed login attempts',
            'deleted': deleted
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to cleanup failed login attempts")
        return jsonify({'error': 'Failed to cleanup failed login attempts'}), 500


@app.route('/api/admin/console/users', methods=['GET'])
@login_required
@admin_required
def admin_console_users():
    """Admin console endpoint for user management overview.
    
    Returns all users with their roles and status.
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: User list
        403: Permission denied
    """
    try:
        users = User.query.order_by(User.created_at.desc()).all()

        serialized_users = [_serialize_user_with_last_login(user) for user in users]

        role_counts = {
            'admin': sum(1 for u in serialized_users if u['role'] == 'admin'),
            'artist-guest': sum(1 for u in serialized_users if u['role'] == 'artist-guest'),
            'guest': sum(1 for u in serialized_users if u['role'] == 'guest'),
            'inactive': sum(1 for u in serialized_users if not u['is_active'])
        }

        return jsonify({
            'users': serialized_users,
            'total': len(users),
            'role_counts': role_counts
        }), 200
    except Exception as e:
        app.logger.exception("Failed to fetch users")
        return jsonify({'error': 'Failed to fetch users'}), 500


def _serialize_user_with_last_login(user):
    """Serialize a user with normalized role and last login timestamp."""
    last_login = AuditLog.query.filter_by(
        user_id=user.id,
        event_type='login_success'
    ).order_by(AuditLog.created_at.desc()).first()

    return {
        'id': user.id,
        'email': user.email,
        'role': user.normalized_role,
        'is_active': user.is_active,
        'deleted_at': user.deleted_at.isoformat() if getattr(user, 'deleted_at', None) else None,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': last_login.created_at.isoformat() if last_login and last_login.created_at else None,
        'is_bootstrap_admin': _is_bootstrap_admin(user)
    }


def _update_expired_password_resets():
    """Automatically update approved password reset requests that have expired."""
    now = datetime.now(timezone.utc)
    
    # get all approved requests with expiration times
    approved_requests = PasswordResetRequest.query.filter(
        PasswordResetRequest.status == 'approved',
        PasswordResetRequest.expires_at.isnot(None)
    ).all()
    
    app.logger.debug(f"Checking {len(approved_requests)} approved password reset requests for expiration")
    
    expired_requests = []
    for req in approved_requests:
        expires_at = req.expires_at
        # ensure timezone-aware comparison
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        app.logger.debug(f"Request {req.id}: expires_at={expires_at}, now={now}, expired={expires_at <= now}")
        
        if expires_at <= now:
            expired_requests.append(req)
    
    if expired_requests:
        app.logger.info(f"Found {len(expired_requests)} expired password reset request(s), updating status...")
        for req in expired_requests:
            req.status = 'expired'
            req.expires_at = None
            log_audit_event(
                'password_reset_expired',
                user_id=req.user_id,
                email=req.email,
                details={
                    'request_id': req.id,
                    'auto_expired': True
                }
            )
        
        try:
            db.session.commit()
            app.logger.info(f"Successfully auto-expired {len(expired_requests)} password reset request(s)")
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to auto-expire password reset requests")


def _serialize_password_reset_request(request_obj):
    """Serialize password reset request for admin console."""
    def _iso(value):
        return value.isoformat() if value else None

    expires_at = request_obj.expires_at
    now = datetime.now(timezone.utc)
    
    # ensure both datetimes are timezone-aware for comparison
    is_expired = False
    if expires_at:
        expires_at_aware = expires_at
        if expires_at.tzinfo is None:
            # assume naive datetime is UTC
            expires_at_aware = expires_at.replace(tzinfo=timezone.utc)
        is_expired = expires_at_aware <= now

    return {
        'id': request_obj.id,
        'email': request_obj.email,
        'user_id': request_obj.user_id,
        'status': 'expired' if request_obj.status == 'approved' and is_expired else request_obj.status,
        'user_message': request_obj.user_message,
        'admin_message': request_obj.admin_message,
        'approved_by_id': request_obj.approved_by_id,
        'created_at': _iso(request_obj.created_at),
        'updated_at': _iso(request_obj.updated_at),
        'approved_at': _iso(request_obj.approved_at),
        'expires_at': _iso(expires_at),
        'resolved_at': _iso(request_obj.resolved_at),
        'code_hint': request_obj.reset_code_hint,
        'has_active_code': bool(request_obj.reset_code_hash and not is_expired)
    }


def _generate_reset_code(length=12):
    """Generate a human-shareable reset code (avoids ambiguous characters)."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _sanitize_admin_note(note_value):
    """Normalize admin-provided notes/messages for reset workflow."""
    if note_value is None:
        return None
    cleaned = sanitize_html(str(note_value).strip())
    if not cleaned:
        return None
    if len(cleaned) > MAX_PASSWORD_RESET_MESSAGE_LENGTH:
        return cleaned[:MAX_PASSWORD_RESET_MESSAGE_LENGTH]
    return cleaned


def _active_admin_count(exclude_user_id=None):
    """Return count of active admins, optionally excluding a specific user."""
    query = User.query.filter(User.role == 'admin', User.is_active == True)
    if exclude_user_id:
        query = query.filter(User.id != exclude_user_id)
    return query.count()


def _is_bootstrap_admin(user):
    """Check if the user matches the bootstrap admin email."""
    try:
        return user.email and user.email.lower() == BOOTSTRAP_ADMIN_EMAIL
    except Exception:
        return False


def _maybe_alert_role_change_spike(event_type):
    """Log warning on spikes of role changes (promote/demote) in last 10 minutes."""
    try:
        window_start = datetime.now(timezone.utc) - timedelta(minutes=10)
        count = AuditLog.query.filter(
            AuditLog.event_type == event_type,
            AuditLog.created_at >= window_start
        ).count()
        if count >= 3:
            app.logger.warning(
                "Security alert: spike in role changes",
                extra={'event_type': event_type, 'count_last_hour': count}
            )
    except Exception:
        pass


@app.route('/api/admin/console/users/<int:user_id>/promote', methods=['POST'])
@login_required
@admin_required
@limiter.limit("100 per minute")
def promote_user(user_id):
    """Promote a user one step up the role ladder."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    previous_role = target.normalized_role or 'guest'
    previous_active = target.is_active

    # Debug payload for troubleshooting role issues (safe to keep minimal)
    debug_payload = {
        'target_id': target.id,
        'target_role': target.role,
        'target_normalized_role': previous_role,
        'target_active': target.is_active,
        'requestor_id': current_user.id,
        'requestor_role': current_user.role
    }

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot modify the bootstrap admin account', 'debug': debug_payload}), 403

    if previous_role == 'admin':
        app.logger.warning("[promote] blocking upgrade for admin target=%s", debug_payload)
        return jsonify({'error': 'User is already at the highest role', 'debug': debug_payload}), 400

    app.logger.warning("[promote] proceed payload=%s", debug_payload)

    target.promote()
    new_role = target.normalized_role

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to promote user'}), 500

    log_audit_event(
        'user_promoted',
        user_id=target.id,
        email=target.email,
        details={
            'previous_role': previous_role,
            'new_role': new_role,
            'previous_active': previous_active,
            'new_active': target.is_active,
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        }
    )

    _maybe_alert_role_change_spike('user_promoted')

    return jsonify({
        'message': 'User promoted successfully',
        'user': _serialize_user_with_last_login(target)
    }), 200


@app.route('/api/admin/console/users/<int:user_id>/demote', methods=['POST'])
@login_required
@admin_required
@limiter.limit("100 per minute")
def demote_user(user_id):
    """Demote a user one step down the role ladder."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Prevent self-demotion to avoid lockouts
    if str(target.id) == str(current_user.id):
        return jsonify({'error': 'You cannot demote your own account'}), 403

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot modify the bootstrap admin account'}), 403

    previous_role = target.normalized_role or 'guest'
    previous_active = target.is_active

    if previous_role == 'guest':
        return jsonify({'error': 'User is already at the lowest role'}), 400

    if previous_role == 'admin' and target.is_active and _active_admin_count(exclude_user_id=target.id) == 0:
        return jsonify({'error': 'Cannot demote the last active admin'}), 400

    target.demote()
    new_role = target.normalized_role

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to demote user'}), 500

    log_audit_event(
        'user_demoted',
        user_id=target.id,
        email=target.email,
        details={
            'previous_role': previous_role,
            'new_role': new_role,
            'previous_active': previous_active,
            'new_active': target.is_active,
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        }
    )

    _maybe_alert_role_change_spike('user_demoted')

    return jsonify({
        'message': 'User demoted successfully',
        'user': _serialize_user_with_last_login(target)
    }), 200


@app.route('/api/admin/console/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
@limiter.limit("100 per minute")
def toggle_user_active(user_id):
    """Toggle a user's active status (soft delete/restore)."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot deactivate the bootstrap admin account'}), 403

    previous_role = target.normalized_role or 'guest'
    previous_active = target.is_active
    new_active = not previous_active

    if not new_active and str(target.id) == str(current_user.id):
        return jsonify({'error': 'You cannot deactivate your own account'}), 403

    if not new_active and previous_role == 'admin' and _active_admin_count(exclude_user_id=target.id) == 0:
        return jsonify({'error': 'Cannot deactivate the last active admin'}), 400

    target.is_active = new_active

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user status'}), 500

    event_type = 'user_reactivated' if new_active else 'user_deactivated'
    log_audit_event(
        event_type,
        user_id=target.id,
        email=target.email,
        details={
            'previous_role': previous_role,
            'new_role': target.normalized_role,
            'previous_active': previous_active,
            'new_active': new_active,
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        }
    )

    return jsonify({
        'message': 'User reactivated' if new_active else 'User deactivated',
        'user': _serialize_user_with_last_login(target)
    }), 200


@app.route('/api/admin/console/users/<int:user_id>/force-logout', methods=['POST'])
@login_required
@admin_required
@limiter.limit("50 per minute")
def force_logout_user(user_id):
    """Force logout a user by rotating their session token."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Avoid locking out your own active session
    if str(target.id) == str(current_user.id):
        return jsonify({'error': 'You cannot force logout your own active session'}), 403

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot force logout the bootstrap admin account'}), 403

    target.remember_token = secrets.token_urlsafe(32)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to force logout user'}), 500

    log_audit_event(
        'user_forced_logout',
        user_id=target.id,
        email=target.email,
        details={
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        }
    )

    return jsonify({
        'message': 'User session revoked',
        'user': _serialize_user_with_last_login(target)
    }), 200


@app.route('/api/admin/console/database-info', methods=['GET'])
@login_required
@admin_required
def admin_console_database_info():
    """Admin console endpoint for database metadata.
    
    Returns table row counts and database engine information.
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Database information
        403: Permission denied
    """
    try:
        # Get table row counts
        table_counts = {
            'artist': Artist.query.count(),
            'artwork': Artwork.query.count(),
            'artwork_photos': ArtworkPhoto.query.count(),
            'storage': Storage.query.count(),
            'users': User.query.count(),
            'audit_logs': AuditLog.query.count(),
            'failed_login_attempts': FailedLoginAttempt.query.count()
        }
        
        # Get database engine info
        db_engine = db.engine.url.drivername if hasattr(db.engine, 'url') else 'unknown'
        db_name = db.engine.url.database if hasattr(db.engine, 'url') else 'unknown'
        
        return jsonify({
            'table_counts': table_counts,
            'engine': {
                'name': db_engine,
                'database': db_name
            }
        }), 200
    except Exception as e:
        app.logger.exception("Failed to fetch database info")
        return jsonify({'error': 'Failed to fetch database information'}), 500


@app.route('/api/admin/console/users/<int:user_id>/soft-delete', methods=['POST'])
@login_required
@admin_required
@limiter.limit("50 per minute")
def soft_delete_user(user_id):
    """Soft delete a user (sets is_active=False and deleted_at timestamp)."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot delete the bootstrap admin account'}), 403

    if target.id == current_user.id:
        return jsonify({'error': 'You cannot delete your own account here. Use self-delete instead.'}), 403

    from datetime import datetime, timezone
    target.is_active = False
    target.deleted_at = datetime.now(timezone.utc)

    try:
        db.session.commit()
        log_audit_event('user_soft_deleted', user_id=target.id, email=target.email, details={
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        })
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to soft delete user'}), 500

    return jsonify({'message': 'User soft-deleted', 'user': _serialize_user_with_last_login(target)}), 200


@app.route('/api/admin/console/users/<int:user_id>/restore', methods=['POST'])
@login_required
@admin_required
@limiter.limit("50 per minute")
def restore_user(user_id):
    """Restore a soft-deleted user (reactivate account and clear deleted_at)."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    if target.deleted_at is None:
        return jsonify({'error': 'User is not deleted'}), 400

    target.is_active = True
    target.deleted_at = None

    try:
        db.session.commit()
        log_audit_event('user_restored', user_id=target.id, email=target.email, details={
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        })
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to restore user'}), 500

    return jsonify({'message': 'User restored', 'user': _serialize_user_with_last_login(target)}), 200


@app.route('/api/admin/console/users/purge-deleted', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per minute")
def purge_deleted_users():
    """Hard delete users with deleted_at older than a given number of days (default 30)."""
    data = request.get_json(silent=True) or {}
    days = int(data.get('days', 30))

    cutoff = None
    if days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        # Fetch users to purge
        query = User.query.filter(User.deleted_at.isnot(None))
        if cutoff:
            query = query.filter(User.deleted_at < cutoff)
        users_to_delete = query.all()

        deleted_count = 0
        for user in users_to_delete:
            if _is_bootstrap_admin(user):
                continue
            # Null out artist.user_id links
            Artist = globals().get('Artist')
            if Artist:
                Artist.query.filter(Artist.user_id == user.id).update({'user_id': None})
            db.session.delete(user)
            deleted_count += 1

        db.session.commit()
        return jsonify({'message': f'Purged {deleted_count} users', 'deleted': deleted_count}), 200
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to purge deleted users")
        return jsonify({'error': 'Failed to purge deleted users'}), 500


@app.route('/api/admin/console/users/<int:user_id>/hard-delete', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per minute")
def hard_delete_user(user_id):
    """Immediately and permanently delete a user by ID."""
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    if _is_bootstrap_admin(target):
        return jsonify({'error': 'Cannot delete the bootstrap admin account'}), 403

    if target.id == current_user.id:
        return jsonify({'error': 'You cannot delete your own account here. Use self-delete instead.'}), 403

    try:
        # Null out artist links
        Artist = globals().get('Artist')
        if Artist:
            Artist.query.filter(Artist.user_id == target.id).update({'user_id': None})

        db.session.delete(target)
        db.session.commit()

        log_audit_event('user_hard_deleted', user_id=target.id, email=target.email, details={
            'acted_by_id': current_user.id,
            'acted_by_email': current_user.email
        })

        return jsonify({'message': 'User permanently deleted', 'deleted_user_id': user_id}), 200
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to hard delete user")
        return jsonify({'error': 'Failed to permanently delete user'}), 500


# Password reset admin workflow endpoints
@app.route('/api/admin/console/password-resets', methods=['GET'])
@login_required
@admin_required
@limiter.limit("60 per minute")
def admin_console_password_resets():
    """List password reset requests for admin review."""
    # automatically update expired requests before listing
    _update_expired_password_resets()
    
    status_filter = (request.args.get('status') or 'all').strip().lower()
    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 10)

    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = max(1, min(50, int(per_page)))
    except (TypeError, ValueError):
        per_page = 10

    query = PasswordResetRequest.query
    now = datetime.now(timezone.utc)

    if status_filter in ('pending', 'approved', 'denied', 'completed'):
        query = query.filter(PasswordResetRequest.status == status_filter)
    elif status_filter == 'open':
        query = query.filter(PasswordResetRequest.status.in_(['pending', 'approved']))
    elif status_filter == 'expired':
        query = query.filter(
            db.or_(
                PasswordResetRequest.status == 'expired',
                db.and_(
                    PasswordResetRequest.status == 'approved',
                    PasswordResetRequest.expires_at.isnot(None),
                    PasswordResetRequest.expires_at < now
                )
            )
        )
    elif status_filter == 'all':
        pass
    else:
        # Unknown filter falls back to pending for safety
        query = query.filter(PasswordResetRequest.status == 'pending')

    pagination = query.order_by(PasswordResetRequest.created_at.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return jsonify({
        'requests': [_serialize_password_reset_request(req) for req in pagination.items],
        'pagination': {
            'page': pagination.page,
            'pages': pagination.pages or (1 if pagination.total else 0),
            'per_page': per_page,
            'total': pagination.total
        }
    }), 200


@app.route('/api/admin/console/password-resets/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def approve_password_reset_request(request_id):
    """Generate a manual reset code for a pending request."""
    reset_request = db.session.get(PasswordResetRequest, request_id)
    if not reset_request:
        return jsonify({'error': 'Request not found'}), 404

    data = request.get_json(silent=True) or {}
    admin_message = _sanitize_admin_note(data.get('message'))
    expires_minutes = data.get('expires_in_minutes', PASSWORD_RESET_CODE_TTL_MINUTES)
    try:
        expires_minutes = int(expires_minutes)
    except (TypeError, ValueError):
        expires_minutes = PASSWORD_RESET_CODE_TTL_MINUTES
    # allow minimum of 1 minute for testing, max 1440 (24 hours)
    expires_minutes = max(1, min(1440, expires_minutes))

    if reset_request.status == 'completed':
        return jsonify({'error': 'Request already completed'}), 400

    reset_code = _generate_reset_code()
    reset_request.reset_code_hash = bcrypt.generate_password_hash(reset_code).decode('utf-8')
    reset_request.reset_code_hint = reset_code[-4:]
    reset_request.status = 'approved'
    if admin_message is not None:
        reset_request.admin_message = admin_message
    reset_request.approved_by_id = current_user.id
    now = datetime.now(timezone.utc)
    reset_request.approved_at = now
    reset_request.resolved_at = None
    reset_request.expires_at = now + timedelta(minutes=expires_minutes)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to approve password reset request")
        return jsonify({'error': 'Failed to approve password reset request'}), 500

    log_audit_event(
        'password_reset_approved',
        user_id=reset_request.user_id,
        email=reset_request.email,
        details={
            'request_id': reset_request.id,
            'expires_at': reset_request.expires_at.isoformat() if reset_request.expires_at else None,
            'approved_by_id': current_user.id
        }
    )

    return jsonify({
        'message': 'Reset code generated. Share it securely with the requester.',
        'reset_code': reset_code,
        'request': _serialize_password_reset_request(reset_request)
    }), 200


@app.route('/api/admin/console/password-resets/<int:request_id>/deny', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def deny_password_reset_request(request_id):
    """Deny a password reset request with an optional admin note."""
    reset_request = db.session.get(PasswordResetRequest, request_id)
    if not reset_request:
        return jsonify({'error': 'Request not found'}), 404

    if reset_request.status == 'completed':
        return jsonify({'error': 'Request already completed'}), 400

    data = request.get_json(silent=True) or {}
    admin_message = _sanitize_admin_note(data.get('message'))

    reset_request.status = 'denied'
    reset_request.reset_code_hash = None
    reset_request.reset_code_hint = None
    reset_request.expires_at = None
    reset_request.resolved_at = datetime.now(timezone.utc)
    if admin_message is not None:
        reset_request.admin_message = admin_message

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to deny password reset request")
        return jsonify({'error': 'Failed to deny password reset request'}), 500

    log_audit_event(
        'password_reset_denied',
        user_id=reset_request.user_id,
        email=reset_request.email,
        details={
            'request_id': reset_request.id,
            'acted_by_id': current_user.id
        }
    )

    return jsonify({
        'message': 'Request denied',
        'request': _serialize_password_reset_request(reset_request)
    }), 200


@app.route('/api/admin/console/password-resets/<int:request_id>/mark-complete', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per minute")
def complete_password_reset_request(request_id):
    """Mark a request as completed/closed when handled out-of-band."""
    reset_request = db.session.get(PasswordResetRequest, request_id)
    if not reset_request:
        return jsonify({'error': 'Request not found'}), 404

    data = request.get_json(silent=True) or {}
    admin_message = _sanitize_admin_note(data.get('message'))

    reset_request.status = 'completed'
    reset_request.reset_code_hash = None
    reset_request.reset_code_hint = None
    reset_request.expires_at = None
    reset_request.resolved_at = datetime.now(timezone.utc)
    if admin_message is not None:
        reset_request.admin_message = admin_message

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to mark password reset request complete")
        return jsonify({'error': 'Failed to mark request complete'}), 500

    log_audit_event(
        'password_reset_marked_complete',
        user_id=reset_request.user_id,
        email=reset_request.email,
        details={
            'request_id': reset_request.id,
            'acted_by_id': current_user.id
        }
    )

    return jsonify({
        'message': 'Request marked complete',
        'request': _serialize_password_reset_request(reset_request)
    }), 200


@app.route('/api/admin/console/password-resets/<int:request_id>', methods=['DELETE', 'OPTIONS'])
def delete_password_reset_request(request_id):
    """Delete a password reset request."""
    if request.method == 'OPTIONS':
        # handle CORS preflight
        return '', 200
    
    # apply decorators manually for DELETE method
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    reset_request = db.session.get(PasswordResetRequest, request_id)
    if not reset_request:
        return jsonify({'error': 'Request not found'}), 404

    email = reset_request.email
    user_id = reset_request.user_id
    previous_status = reset_request.status
    
    try:
        db.session.delete(reset_request)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to delete password reset request")
        return jsonify({'error': 'Failed to delete password reset request'}), 500

    log_audit_event(
        'password_reset_deleted',
        user_id=user_id,
        email=email,
        details={
            'request_id': request_id,
            'deleted_by_id': current_user.id,
            'previous_status': previous_status
        }
    )

    return jsonify({
        'message': 'Password reset request deleted successfully'
    }), 200


@app.route('/api/account/admin-info', methods=['GET'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def get_personal_admin_info():
    """Get personal admin account information and statistics."""
    try:
        # get recent audit log entries for this admin (last 10)
        recent_actions = AuditLog.query.filter(
            AuditLog.user_id == current_user.id
        ).order_by(AuditLog.created_at.desc()).limit(10).all()
        
        # count admin actions
        password_resets_approved = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'password_reset_approved'
        ).count()
        
        password_resets_denied = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'password_reset_denied'
        ).count()
        
        users_promoted = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'user_promoted'
        ).count()
        
        users_demoted = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'user_demoted'
        ).count()
        
        # get personal upload statistics
        photos_uploaded = ArtworkPhoto.query.filter(
            ArtworkPhoto.uploaded_by == current_user.id
        ).count()
        
        # get artworks count (if user has assigned artists)
        assigned_artists = Artist.query.filter_by(user_id=current_user.id).all()
        artist_ids = [a.artist_id for a in assigned_artists]
        artworks_count = 0
        if artist_ids:
            artworks_count = Artwork.query.filter(
                Artwork.artist_id.in_(artist_ids),
                Artwork.is_deleted == False
            ).count()
        
        # get last login from audit log
        last_login = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'login_success'
        ).order_by(AuditLog.created_at.desc()).first()
        
        # get password/email change history
        password_changed = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'password_changed'
        ).order_by(AuditLog.created_at.desc()).first()
        
        email_changed = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type == 'email_changed'
        ).order_by(AuditLog.created_at.desc()).first()
        
        def _iso(value):
            return value.isoformat() if value else None
        
        return jsonify({
            'account_info': {
                'email': current_user.email,
                'role': current_user.normalized_role,
                'created_at': _iso(current_user.created_at),
                'last_login': _iso(last_login.created_at) if last_login else None,
                'password_last_changed': _iso(password_changed.created_at) if password_changed else None,
                'email_last_changed': _iso(email_changed.created_at) if email_changed else None
            },
            'statistics': {
                'password_resets_approved': password_resets_approved,
                'password_resets_denied': password_resets_denied,
                'users_promoted': users_promoted,
                'users_demoted': users_demoted,
                'photos_uploaded': photos_uploaded,
                'artworks_count': artworks_count,
                'assigned_artists': len(assigned_artists)
            },
            'recent_actions': [
                {
                    'id': log.id,
                    'event_type': log.event_type,
                    'created_at': _iso(log.created_at),
                    'details': json.loads(log.details) if log.details else None
                }
                for log in recent_actions
            ]
        }), 200
    except Exception as e:
        app.logger.exception("Error in get_personal_admin_info")
        return jsonify({'error': 'Failed to load admin information'}), 500


# CLI confirmation tokens storage (in-memory, expires after 30 seconds)
_cli_confirmation_tokens = {}


@app.route('/api/admin/console/cli/help', methods=['GET'])
@login_required
@admin_required
def admin_console_cli_help():
    """Admin console CLI help endpoint.
    
    Returns available commands, syntax, and examples for auto-complete.
    
    Security:
        - Requires authentication
        - Requires admin role
    
    Returns:
        200: Help information
        403: Permission denied
    """
    try:
        from cli_parser import CLIParser
        help_info = CLIParser.get_help()
        return jsonify(help_info), 200
    except Exception as e:
        app.logger.exception("Failed to fetch CLI help")
        return jsonify({'error': 'Failed to fetch CLI help'}), 500


@app.route('/api/admin/console/cli', methods=['POST'])
@login_required
@admin_required
def admin_console_cli():
    """Admin console CLI endpoint.
    
    Executes CLI commands with validation and safety checks.
    
    Security:
        - Requires authentication
        - Requires admin role
        - Write mode must be explicitly enabled
        - Delete operations require double confirmation
    
    Request Body:
        command (str, required): CLI command to execute
        write_mode (bool, optional): Whether write operations are allowed (default: false)
        confirmation_token (str, optional): Token for delete confirmation
        
    Returns:
        200: Command executed successfully
        400: Invalid command or parameters
        403: Permission denied or write mode required
    """
    try:
        from cli_parser import CLIParser, CLIParseError
        from cli_executor import CLIExecutor, CLIExecutionError
        import secrets
        
        # Parse JSON body (force=True to handle CSRF-exempt endpoints)
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Invalid JSON in request body',
                'output': f'Failed to parse request: {str(e)}'
            }), 400
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Request body is required',
                'output': 'Request body is required'
            }), 400
        
        command = data.get('command', '').strip()
        if not command:
            return jsonify({
                'success': False,
                'error': 'Command is required',
                'output': 'Command is required'
            }), 400
        
        write_mode = data.get('write_mode', False)
        confirmation_token = data.get('confirmation_token')
        
        # Parse command
        try:
            parsed_command = CLIParser.parse(command)
        except CLIParseError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'output': f'Parse error: {str(e)}'
            }), 400
        
        # Initialize executor
        models = {
            'Artist': Artist,
            'Artwork': Artwork,
            'Storage': Storage,
            'ArtworkPhoto': ArtworkPhoto,
            'User': User
        }
        executor = CLIExecutor(db, models)
        
        # Handle delete confirmation flow
        if parsed_command['action'] == 'delete':
            entity = parsed_command['entity']
            entity_id = parsed_command['entity_id']
            
            if confirmation_token:
                # Second confirmation - verify token
                token_data = _cli_confirmation_tokens.get(confirmation_token)
                if not token_data:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid or expired confirmation token',
                        'output': 'Confirmation token is invalid or has expired. Please start over.'
                    }), 400
                
                if token_data.get('user_id') != current_user.id:
                    return jsonify({
                        'success': False,
                        'error': 'Confirmation token does not belong to this user',
                        'output': 'Confirmation token was issued to a different user. Please start over.'
                    }), 403
                
                # Verify token matches this delete operation
                if token_data['entity'] != entity or token_data['entity_id'] != entity_id:
                    return jsonify({
                        'success': False,
                        'error': 'Confirmation token does not match this operation',
                        'output': 'Confirmation token does not match. Please start over.'
                    }), 400
                
                # Execute delete
                try:
                    result = executor.execute_delete(entity, entity_id, current_user.id, current_user.email)
                    # Remove used token
                    _cli_confirmation_tokens.pop(confirmation_token, None)
                    return jsonify(result), 200
                except CLIExecutionError as e:
                    return jsonify({
                        'success': False,
                        'error': str(e),
                        'output': f'Delete failed: {str(e)}'
                    }), 400
            else:
                # First delete request - return confirmation request
                preview_result = executor._execute_delete_preview(entity, entity_id)
                
                # Generate confirmation token
                token = secrets.token_urlsafe(32)
                _cli_confirmation_tokens[token] = {
                    'entity': entity,
                    'entity_id': entity_id,
                    'user_id': current_user.id,
                    'created_at': datetime.now(timezone.utc)
                }
                
                # Clean up old tokens (older than 30 seconds)
                now = datetime.now(timezone.utc)
                expired_tokens = [
                    t for t, data in _cli_confirmation_tokens.items()
                    if (now - data['created_at']).total_seconds() > 30
                ]
                for t in expired_tokens:
                    _cli_confirmation_tokens.pop(t, None)
                
                return jsonify({
                    'success': True,
                    'output': preview_result['output'],
                    'data': preview_result['data'],
                    'requires_confirmation': True,
                    'confirmation_token': token
                }), 200
        
        # Execute other commands
        try:
            result = executor.execute(
                parsed_command,
                write_mode=write_mode,
                user_id=current_user.id,
                user_email=current_user.email
            )
            return jsonify(result), 200
        except CLIExecutionError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'output': f'Execution error: {str(e)}'
            }), 400
            
    except ImportError as e:
        app.logger.exception("Failed to import CLI modules")
        return jsonify({
            'success': False,
            'error': 'CLI modules not available',
            'output': f'Failed to import CLI modules: {str(e)}'
        }), 500
    except Exception as e:
        app.logger.exception("Failed to execute CLI command")
        error_msg = str(e)
        # Make sure we return JSON even if there's an unexpected error
        try:
            return jsonify({
                'success': False,
                'error': 'Internal server error',
                'output': f'Failed to execute command: {error_msg}'
            }), 500
        except Exception:
            # Fallback if jsonify itself fails
            return jsonify({
                'success': False,
                'error': 'Internal server error',
                'output': 'An unexpected error occurred'
            }), 500


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
    bootstrap_email = BOOTSTRAP_ADMIN_EMAIL
    
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
                # bootstrap admin doesn't exist - require explicit password in secure environments
                password_env = os.getenv('BOOTSTRAP_ADMIN_PASSWORD')
                if not password_env:
                    if not allow_insecure_cookies and not app.config.get('TESTING', False):
                        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must be set to create the bootstrap admin")
                    # For local dev, auto-generate a strong password and emit once to stdout
                    password_env = secrets.token_urlsafe(24)
                    print("generated development bootstrap admin password (store securely):")
                    print(password_env)

                hashed_password = bcrypt.generate_password_hash(password_env).decode('utf-8')
                
                admin_user = User(
                    email=bootstrap_email,
                    hashed_password=hashed_password,
                    role='admin',
                    created_at=datetime.now(timezone.utc)
                )
                
                db.session.add(admin_user)
                db.session.commit()
                print(f"created bootstrap admin: {bootstrap_email}")
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


from apscheduler.schedulers.background import BackgroundScheduler
from scheduled_deletes import scheduled_artwork_deletion, scheduled_artist_deletion

scheduler = None
# scheduler for deletion of soft-deleted items over 30 days
def start_deletion_scheduler():
    """ The scheduler for running auto-deletion tasks
        for items such as artwork that have been soft-deleted
        for longer than 30 days. Will only start in the case 
        of there being no existing scheduler to prevent
        multiple instances of a scheduler.
    """
    global scheduler
    if scheduler is None:
        scheduler = BackgroundScheduler(daemon=True)
        scheduler.add_job(
            func=scheduled_artwork_deletion,
            trigger='interval',
            days=1
        )
        scheduler.add_job(
            func=scheduled_artist_deletion,
            trigger='interval',
            days=1
        )
        scheduler.start()
        app.logger.info("Deletion Scheduler started - using APScheduler.")
    else:
        app.logger.info("Deletion Scheduler already running, skipping start.")
    

# for stopping the deletion scheduler, mostly for testing purposes
def stop_deletion_scheduler():
    """ Function to stop the deletion scheduler.

        Mostly for testing purposes, since the
        scheduler runs in the backgound and calling
        docker compose down automatically shuts down
        the scheduler due is specifically being a daemon. 
        
        Allows for control during testing, as well as a 
        fallback in the case of wanting to stop scheduled
        deletions. 
    """
    global scheduler
    if scheduler:
        scheduler.shutdown(wait=False)
        scheduler = None
        app.logger.info("Deletion Scheduler has stopped - using APScheduler.")

# ensure scheduler not running during testing - uncomment to run schedular
#if not app.config.get("TESTING", False):
#    start_deletion_scheduler()

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
