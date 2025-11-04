from flask import Flask, jsonify, request
import os
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager
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
Artist, Artwork, Storage, FlatFile, WallSpace, Rack = init_tables(db)

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

            items.append({
                'type': 'artwork',
                'id': artwork.artwork_num,
                'title': artwork.artwork_ttl,
                'medium': artwork.artwork_medium,
                'thumbnail': None,
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

# TODO(security, JC): Implement JWT token authentication for API endpoints (optional)
# TODO(security, JC): Add file upload endpoint with security checks (file type, size, virus scan)

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
