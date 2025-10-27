"""Tests for authentication endpoints and session security."""
import pytest
from app import app, db, User


@pytest.fixture
def client():
    """Create a test client with a fresh database and CSRF disabled for convenience."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False  # disable csrf for most tests
    app.config['SESSION_COOKIE_SECURE'] = False  # allow testing without https
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def csrf_client():
    """Create a test client with CSRF protection enabled."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = True  # enable csrf for security tests
    app.config['SESSION_COOKIE_SECURE'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


def get_csrf_token(client):
    """helper function to get csrf token from the server."""
    response = client.get('/auth/csrf-token')
    return response.get_json()['csrf_token']


@pytest.fixture
def sample_user():
    """Sample user data for testing."""
    return {
        'email': 'test@example.com',
        'password': 'SecurePass123'
    }


@pytest.fixture
def admin_user():
    """Sample admin user data for testing (must be manually promoted to admin)."""
    return {
        'email': 'admin@example.com',
        'password': 'AdminPass123'
    }


class TestUserRegistration:
    """Tests for user registration endpoint."""
    
    def test_register_success(self, client, sample_user):
        """Test successful user registration."""
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 201
        data = response.get_json()
        assert data['message'] == 'User registered successfully'
        assert data['user']['email'] == sample_user['email']
        assert data['user']['role'] == sample_user['role']
        assert 'id' in data['user']
        assert 'created_at' in data['user']
        assert 'password' not in data['user']
        assert 'hashed_password' not in data['user']
    
    def test_register_duplicate_email(self, client, sample_user):
        """Test registration with duplicate email fails."""
        # Register first user
        client.post('/auth/register', json=sample_user)
        
        # Try to register again with same email
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Email already registered' in data['error']
    
    def test_register_invalid_email(self, client, sample_user):
        """Test registration with invalid email format."""
        sample_user['email'] = 'invalid-email'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid email format' in data['error']
    
    def test_register_missing_email(self, client, sample_user):
        """Test registration without email."""
        del sample_user['email']
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Email is required' in data['error']
    
    def test_register_weak_password(self, client, sample_user):
        """Test registration with weak password."""
        sample_user['password'] = 'weak'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Password must be at least 8 characters' in data['error']
    
    def test_register_password_no_uppercase(self, client, sample_user):
        """Test registration with password missing uppercase."""
        sample_user['password'] = 'securepass123'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'uppercase letter' in data['error']
    
    def test_register_password_no_lowercase(self, client, sample_user):
        """Test registration with password missing lowercase."""
        sample_user['password'] = 'SECUREPASS123'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'lowercase letter' in data['error']
    
    def test_register_password_no_digit(self, client, sample_user):
        """Test registration with password missing digit."""
        sample_user['password'] = 'SecurePassword'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'digit' in data['error']
    
    def test_register_ignores_role_parameter(self, client, sample_user):
        """test that role parameter is ignored and all users are created as visitor (security fix)."""
        # try to register as admin (should be ignored)
        sample_user['role'] = 'admin'
        response = client.post('/auth/register', json=sample_user)
        
        assert response.status_code == 201
        data = response.get_json()
        # verify user was created as visitor, not admin
        assert data['user']['role'] == 'visitor'
    
    def test_register_no_data(self, client):
        """Test registration with no JSON data."""
        response = client.post('/auth/register')
        
        # 415 Unsupported Media Type when no Content-Type header is sent
        assert response.status_code == 415


class TestUserLogin:
    """Tests for user login endpoint."""
    
    def test_login_success(self, client, sample_user):
        """Test successful login."""
        # Register user first
        client.post('/auth/register', json=sample_user)
        
        # Login
        login_data = {
            'email': sample_user['email'],
            'password': sample_user['password']
        }
        response = client.post('/auth/login', json=login_data)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Login successful'
        assert data['user']['email'] == sample_user['email']
        assert data['user']['role'] == sample_user['role']
    
    def test_login_with_remember_me(self, client, sample_user):
        """Test login with remember me option."""
        # Register user first
        client.post('/auth/register', json=sample_user)
        
        # Login with remember me
        login_data = {
            'email': sample_user['email'],
            'password': sample_user['password'],
            'remember': True
        }
        response = client.post('/auth/login', json=login_data)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Login successful'
    
    def test_login_invalid_password(self, client, sample_user):
        """Test login with incorrect password."""
        # Register user first
        client.post('/auth/register', json=sample_user)
        
        # Try to login with wrong password
        login_data = {
            'email': sample_user['email'],
            'password': 'WrongPassword123'
        }
        response = client.post('/auth/login', json=login_data)
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid email or password' in data['error']
    
    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent email."""
        login_data = {
            'email': 'nonexistent@example.com',
            'password': 'SomePassword123'
        }
        response = client.post('/auth/login', json=login_data)
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid email or password' in data['error']
    
    def test_login_missing_credentials(self, client):
        """Test login without email or password."""
        response = client.post('/auth/login', json={})
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Email and password are required' in data['error']
    
    def test_login_disabled_account(self, client, sample_user):
        """Test login with disabled account."""
        # Register user
        client.post('/auth/register', json=sample_user)
        
        # Disable the user account
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            user.is_active = False
            db.session.commit()
        
        # Try to login
        login_data = {
            'email': sample_user['email'],
            'password': sample_user['password']
        }
        response = client.post('/auth/login', json=login_data)
        
        assert response.status_code == 403
        data = response.get_json()
        assert 'Account is disabled' in data['error']


class TestUserLogout:
    """Tests for user logout endpoint."""
    
    def test_logout_success(self, client, sample_user):
        """Test successful logout."""
        # Register and login
        client.post('/auth/register', json=sample_user)
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Logout
        response = client.post('/auth/logout')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Logout successful'
    
    def test_logout_not_logged_in(self, client):
        """Test logout without being logged in."""
        response = client.post('/auth/logout')
        
        assert response.status_code == 401


class TestProtectedRoutes:
    """Tests for protected routes and RBAC."""
    
    def test_protected_route_authenticated(self, client, sample_user):
        """Test access to protected route when authenticated."""
        # Register and login
        client.post('/auth/register', json=sample_user)
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Access protected route
        response = client.get('/auth/protected')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'Access granted' in data['message']
    
    def test_protected_route_unauthenticated(self, client):
        """Test access to protected route without authentication."""
        response = client.get('/auth/protected')
        
        assert response.status_code == 401
    
    def test_admin_route_as_admin(self, client, admin_user):
        """Test admin route access with admin role."""
        # Register user (will be visitor by default)
        client.post('/auth/register', json=admin_user)
        
        # Manually promote to admin (simulating admin promotion endpoint)
        with app.app_context():
            user = User.query.filter_by(email=admin_user['email']).first()
            user.role = 'admin'
            db.session.commit()
        
        # Login as admin
        client.post('/auth/login', json={
            'email': admin_user['email'],
            'password': admin_user['password']
        })
        
        # Access admin route
        response = client.get('/auth/admin-only')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'Admin access granted' in data['message']
    
    def test_admin_route_as_visitor(self, client, sample_user):
        """Test admin route access denied for visitor role."""
        # Register and login as visitor
        client.post('/auth/register', json=sample_user)
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Try to access admin route
        response = client.get('/auth/admin-only')
        
        assert response.status_code == 403
        data = response.get_json()
        assert 'Admin access required' in data['error']
    
    def test_get_current_user(self, client, sample_user):
        """Test getting current user info."""
        # Register and login
        client.post('/auth/register', json=sample_user)
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Get current user
        response = client.get('/auth/me')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['user']['email'] == sample_user['email']
        assert data['user']['role'] == sample_user['role']


class TestSessionSecurity:
    """Tests for session security configuration."""
    
    def test_session_cookie_httponly(self, client, sample_user):
        """Test that session cookies have httponly flag."""
        # Register and login
        client.post('/auth/register', json=sample_user)
        response = client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Check for session cookie with httponly
        cookies = response.headers.getlist('Set-Cookie')
        session_cookie = [c for c in cookies if 'session' in c.lower()]
        
        assert len(session_cookie) > 0
        assert 'HttpOnly' in session_cookie[0]
    
    def test_session_cookie_samesite(self, client, sample_user):
        """Test that session cookies have SameSite attribute."""
        # Register and login
        client.post('/auth/register', json=sample_user)
        response = client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # Check for SameSite attribute
        cookies = response.headers.getlist('Set-Cookie')
        session_cookie = [c for c in cookies if 'session' in c.lower()]
        
        assert len(session_cookie) > 0
        assert 'SameSite' in session_cookie[0]
    
    def test_session_cleared_on_logout(self, client, sample_user):
        """Test that session is properly cleared on logout."""
        # Register, login, then logout
        client.post('/auth/register', json=sample_user)
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        client.post('/auth/logout')
        
        # Try to access protected route
        response = client.get('/auth/protected')
        
        assert response.status_code == 401


class TestCSRFProtection:
    """tests for csrf protection on state-changing endpoints."""
    
    def test_csrf_token_endpoint(self, csrf_client):
        """test that csrf token endpoint returns a valid token."""
        response = csrf_client.get('/auth/csrf-token')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'csrf_token' in data
        assert len(data['csrf_token']) > 0
    
    def test_registration_requires_csrf_token(self, csrf_client, sample_user):
        """test that registration endpoint requires csrf token when csrf is enabled."""
        # try to register without csrf token
        response = csrf_client.post('/auth/register', json=sample_user)
        
        # should fail with 400 (csrf validation error)
        assert response.status_code == 400
    
    def test_registration_with_valid_csrf_token(self, csrf_client, sample_user):
        """test that registration succeeds with valid csrf token."""
        # get csrf token
        csrf_token = get_csrf_token(csrf_client)
        
        # register with csrf token in header
        response = csrf_client.post('/auth/register', 
                                    json=sample_user,
                                    headers={'X-CSRFToken': csrf_token})
        
        assert response.status_code == 201
        data = response.get_json()
        assert data['message'] == 'User registered successfully'
    
    def test_login_requires_csrf_token(self, csrf_client, sample_user):
        """test that login endpoint requires csrf token."""
        # first register with csrf (setup)
        csrf_token = get_csrf_token(csrf_client)
        csrf_client.post('/auth/register',
                        json=sample_user,
                        headers={'X-CSRFToken': csrf_token})
        
        # try to login without csrf token
        response = csrf_client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # should fail with 400
        assert response.status_code == 400
    
    def test_logout_requires_csrf_token(self, csrf_client, sample_user):
        """test that logout endpoint requires csrf token."""
        # register and login with csrf (setup)
        csrf_token = get_csrf_token(csrf_client)
        csrf_client.post('/auth/register',
                        json=sample_user,
                        headers={'X-CSRFToken': csrf_token})
        csrf_token = get_csrf_token(csrf_client)  # get fresh token
        csrf_client.post('/auth/login',
                        json={'email': sample_user['email'], 'password': sample_user['password']},
                        headers={'X-CSRFToken': csrf_token})
        
        # try to logout without csrf token
        response = csrf_client.post('/auth/logout')
        
        # should fail with 400
        assert response.status_code == 400

