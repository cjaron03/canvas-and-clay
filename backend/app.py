from flask import Flask, jsonify
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



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
    return jsonify({
        'status': 'healthy',
        'service': 'canvas-clay-backend'
    })

# TODO(security, JC): Create /auth/login endpoint with password hashing (bcrypt)
# TODO(security, JC): Create /auth/register endpoint with input validation
# TODO(security, JC): Create /auth/logout endpoint with session cleanup
# TODO(security, JC): Add role-based access control (RBAC) decorators
# TODO(security, JC): Implement JWT token authentication for API endpoints
# TODO(security, JC): Add file upload endpoint with security checks (file type, size, virus scan)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
