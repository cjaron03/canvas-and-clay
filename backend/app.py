from flask import Flask, jsonify
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})

# Basic configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

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


# TODO(security, JC): Add Flask-Login for user authentication
# TODO(security): Implement CORS policy for frontend access
# TODO(security): Add rate limiting to prevent brute force attacks
# TODO(security): Configure secure session cookies (httponly, secure, samesite)
# TODO(security): Add input validation middleware
# TODO(security): Implement CSRF protection

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

# TODO(security, JC): Create /auth/login endpoint with password hashing (bcrypt)
# TODO(security, JC): Create /auth/register endpoint with input validation
# TODO(security, JC): Create /auth/logout endpoint with session cleanup
# TODO(security, JC): Add role-based access control (RBAC) decorators
# TODO(security, JC): Implement JWT token authentication for API endpoints
# TODO(security, JC): Add file upload endpoint with security checks (file type, size, virus scan)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
