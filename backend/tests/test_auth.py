"""Tests for authentication endpoints and session security."""
import pytest
import time
from datetime import datetime, timezone, timedelta
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
        assert data['user']['role'] == 'visitor'
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
        assert data['user']['role'] == 'visitor'
    
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
        assert data['user']['role'] == 'visitor'


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


class TestBruteForceProtection:
    """tests for brute force protection via account lockout and rate limiting."""
    
    def test_failed_login_increments_counter(self, client, sample_user):
        """test that failed login attempts increment the counter."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # make 1 failed login attempt
        client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': 'WrongPassword123'
        })
        
        # check that counter was incremented
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.failed_login_attempts == 1
            assert user.last_failed_login is not None
    
    def test_account_lockout_after_five_failed_attempts(self, client, sample_user):
        """test that account is locked after 5 failed login attempts."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # make 5 failed login attempts
        for i in range(5):
            response = client.post('/auth/login', json={
                'email': sample_user['email'],
                'password': 'WrongPassword123'
            })
            
            if i < 4:
                # first 4 attempts should return 401 unauthorized
                assert response.status_code == 401
            else:
                # 5th attempt should lock account and return 403 forbidden
                assert response.status_code == 403
                data = response.get_json()
                assert 'Account locked' in data['error']
                assert '15 minutes' in data['error']
        
        # verify account is locked in database
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.failed_login_attempts == 5
            assert user.account_locked_until is not None
            assert user.is_locked is True
    
    def test_locked_account_rejects_login_with_correct_password(self, client, sample_user):
        """test that locked account cannot login even with correct password."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # lock the account by making 5 failed attempts
        for _ in range(5):
            client.post('/auth/login', json={
                'email': sample_user['email'],
                'password': 'WrongPassword123'
            })
        
        # try to login with correct password
        response = client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # should still be locked
        assert response.status_code == 403
        data = response.get_json()
        assert 'temporarily locked' in data['error']
    
    def test_successful_login_resets_failed_attempts(self, client, sample_user):
        """test that successful login resets failed login counter."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # make 3 failed login attempts
        for _ in range(3):
            client.post('/auth/login', json={
                'email': sample_user['email'],
                'password': 'WrongPassword123'
            })
        
        # verify counter is at 3
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.failed_login_attempts == 3
        
        # successful login
        response = client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        assert response.status_code == 200
        
        # verify counter is reset
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.failed_login_attempts == 0
            assert user.account_locked_until is None
            assert user.last_failed_login is None
    
    def test_lockout_expires_after_duration(self, client, sample_user):
        """test that account lockout expires after the lockout duration."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # lock account
        for _ in range(5):
            client.post('/auth/login', json={
                'email': sample_user['email'],
                'password': 'WrongPassword123'
            })
        
        # manually expire the lockout (simulate time passage)
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            # set lockout to expire in the past
            user.account_locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.session.commit()
        
        # try to login with correct password
        response = client.post('/auth/login', json={
            'email': sample_user['email'],
            'password': sample_user['password']
        })
        
        # should succeed since lockout expired
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Login successful'
        
        # verify counter is reset
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.failed_login_attempts == 0
            assert user.account_locked_until is None
    
    def test_failed_login_for_nonexistent_user_does_not_crash(self, client):
        """test that failed login for nonexistent user is handled gracefully."""
        response = client.post('/auth/login', json={
            'email': 'nonexistent@example.com',
            'password': 'SomePassword123'
        })
        
        # should return 401 unauthorized
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid email or password' in data['error']
    
    def test_lockout_time_remaining_calculation(self, client, sample_user):
        """test that lockout error message shows correct time remaining."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # lock account
        for _ in range(5):
            response = client.post('/auth/login', json={
                'email': sample_user['email'],
                'password': 'WrongPassword123'
            })
        
        # verify error message contains time information
        assert response.status_code == 403
        data = response.get_json()
        assert 'Account locked' in data['error']
        assert 'minutes' in data['error']
    
    def test_is_locked_property_false_when_not_locked(self, client, sample_user):
        """test that is_locked property returns false for unlocked accounts."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.is_locked is False
    
    def test_is_locked_property_false_when_lockout_expired(self, client, sample_user):
        """test that is_locked property returns false when lockout has expired."""
        # register user
        client.post('/auth/register', json=sample_user)
        
        # set lockout in the past
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            user.account_locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.session.commit()
        
        with app.app_context():
            user = User.query.filter_by(email=sample_user['email']).first()
            assert user.is_locked is False
    
    def test_multiple_users_independent_lockout(self, client, sample_user):
        """test that account lockout is independent per user."""
        # register two users
        user1 = {'email': 'user1@example.com', 'password': 'SecurePass123'}
        user2 = {'email': 'user2@example.com', 'password': 'SecurePass456'}
        
        client.post('/auth/register', json=user1)
        client.post('/auth/register', json=user2)
        
        # lock user1's account
        for _ in range(5):
            client.post('/auth/login', json={
                'email': user1['email'],
                'password': 'WrongPassword123'
            })
        
        # user1 should be locked
        with app.app_context():
            locked_user = User.query.filter_by(email=user1['email']).first()
            assert locked_user.is_locked is True
        
        # user2 should not be locked
        with app.app_context():
            unlocked_user = User.query.filter_by(email=user2['email']).first()
            assert unlocked_user.is_locked is False
            assert unlocked_user.failed_login_attempts == 0
        
        # user2 should be able to login
        response = client.post('/auth/login', json={
            'email': user2['email'],
            'password': user2['password']
        })
        assert response.status_code == 200

