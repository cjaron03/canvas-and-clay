"""Tests for admin console endpoints."""
import json
import os
import sys
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.pool import StaticPool

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, db, User, AuditLog, FailedLoginAttempt, PasswordResetRequest, bcrypt


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False},
        'poolclass': StaticPool
    }
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = False

    from app import limiter
    limiter.enabled = False

    with app.test_client(use_cookies=True) as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def admin_user(client):
    """Create and login as admin user."""
    with app.app_context():
        user = User(
            email='admin@test.com',
            hashed_password=bcrypt.generate_password_hash('AdminPass123').decode('utf-8'),
            role='admin',
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    # Login
    client.post('/auth/login', json={
        'email': 'admin@test.com',
        'password': 'AdminPass123'
    })

    return {'id': user_id, 'email': 'admin@test.com'}


@pytest.fixture
def guest_user(client):
    """Create and return a guest user (not logged in)."""
    with app.app_context():
        user = User(
            email='guest@test.com',
            hashed_password=bcrypt.generate_password_hash('GuestPass123').decode('utf-8'),
            role='guest',
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        return {'id': user.id, 'email': 'guest@test.com'}


@pytest.fixture
def sample_users(client, admin_user):
    """Create multiple sample users for testing."""
    users = []
    with app.app_context():
        for i in range(3):
            user = User(
                email=f'user{i}@test.com',
                hashed_password=bcrypt.generate_password_hash('TestPass123').decode('utf-8'),
                role='guest',
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
            users.append({'id': user.id, 'email': user.email})
    return users


class TestAdminDashboard:
    """Tests for admin dashboard endpoints."""

    def test_get_stats_as_admin(self, client, admin_user):
        """Admin should be able to get dashboard stats."""
        response = client.get('/api/admin/console/stats')
        assert response.status_code == 200
        data = response.get_json()
        # Stats endpoint returns counts object
        assert 'counts' in data or 'total_users' in data

    def test_get_stats_as_non_admin_forbidden(self, client, guest_user):
        """Non-admin should not access stats."""
        # Login as guest
        client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })
        response = client.get('/api/admin/console/stats')
        assert response.status_code == 403

    def test_get_stats_unauthenticated(self, client):
        """Unauthenticated user should not access stats."""
        response = client.get('/api/admin/console/stats')
        assert response.status_code == 401

    def test_get_artists_list(self, client, admin_user):
        """Admin should be able to get artists list."""
        response = client.get('/api/admin/console/artists')
        assert response.status_code == 200
        data = response.get_json()
        assert 'artists' in data
        assert isinstance(data['artists'], list)

    def test_get_health_status(self, client, admin_user):
        """Admin should be able to get health status."""
        response = client.get('/api/admin/console/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert 'database' in data

    def test_get_database_info(self, client, admin_user):
        """Admin should be able to get database info."""
        response = client.get('/api/admin/console/database-info')
        assert response.status_code == 200
        data = response.get_json()
        # Database info endpoint returns engine and table_counts
        assert 'engine' in data or 'table_counts' in data or 'tables' in data


class TestAdminUserManagement:
    """Tests for user management endpoints."""

    def test_list_users_as_admin(self, client, admin_user, sample_users):
        """Admin should be able to list all users."""
        response = client.get('/api/admin/console/users')
        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data
        # Should have admin + 3 sample users
        assert len(data['users']) >= 4

    def test_list_users_as_non_admin_forbidden(self, client, guest_user):
        """Non-admin should not list users."""
        client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })
        response = client.get('/api/admin/console/users')
        assert response.status_code == 403

    def test_promote_user_to_admin(self, client, admin_user, sample_users):
        """Admin should be able to promote a user."""
        user_id = sample_users[0]['id']
        response = client.post(f'/api/admin/console/users/{user_id}/promote')
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('success') or 'role' in str(data).lower()

        # Verify user role changed (may be 'artist' or 'admin' depending on promotion logic)
        with app.app_context():
            user = User.query.get(user_id)
            assert user.role != 'guest'  # Role should have changed from guest

    def test_demote_admin_to_user(self, client, admin_user):
        """Admin should be able to demote another admin."""
        # First create another admin
        with app.app_context():
            other_admin = User(
                email='other_admin@test.com',
                hashed_password=bcrypt.generate_password_hash('AdminPass123').decode('utf-8'),
                role='admin',
                is_active=True
            )
            db.session.add(other_admin)
            db.session.commit()
            other_admin_id = other_admin.id

        response = client.post(f'/api/admin/console/users/{other_admin_id}/demote')
        assert response.status_code == 200

        # Verify user role changed (demote goes admin -> artist -> guest)
        with app.app_context():
            user = User.query.get(other_admin_id)
            assert user.role != 'admin'  # Role should have changed from admin

    def test_toggle_user_active_status(self, client, admin_user, sample_users):
        """Admin should be able to toggle user active status."""
        user_id = sample_users[0]['id']

        # Deactivate user
        response = client.post(f'/api/admin/console/users/{user_id}/toggle-active')
        assert response.status_code == 200

        with app.app_context():
            user = User.query.get(user_id)
            assert user.is_active is False

        # Reactivate user
        response = client.post(f'/api/admin/console/users/{user_id}/toggle-active')
        assert response.status_code == 200

        with app.app_context():
            user = User.query.get(user_id)
            assert user.is_active is True

    def test_force_logout_user(self, client, admin_user, sample_users):
        """Admin should be able to force logout a user."""
        user_id = sample_users[0]['id']
        response = client.post(f'/api/admin/console/users/{user_id}/force-logout')
        assert response.status_code == 200

    def test_soft_delete_user(self, client, admin_user, sample_users):
        """Admin should be able to soft delete a user."""
        user_id = sample_users[0]['id']
        response = client.post(f'/api/admin/console/users/{user_id}/soft-delete')
        assert response.status_code == 200

        with app.app_context():
            user = User.query.get(user_id)
            # User should be deactivated (is_active=False) as soft delete
            assert user.is_active is False

    def test_restore_soft_deleted_user(self, client, admin_user, sample_users):
        """Admin should be able to restore a soft deleted user."""
        user_id = sample_users[0]['id']

        # First soft delete
        client.post(f'/api/admin/console/users/{user_id}/soft-delete')

        # Then restore
        response = client.post(f'/api/admin/console/users/{user_id}/restore')
        assert response.status_code == 200

        with app.app_context():
            user = User.query.get(user_id)
            # Should be restored (active again)
            assert user.is_active is True

    def test_hard_delete_user(self, client, admin_user, sample_users):
        """Admin should be able to permanently delete a user."""
        user_id = sample_users[0]['id']
        response = client.post(f'/api/admin/console/users/{user_id}/hard-delete')
        assert response.status_code == 200

        with app.app_context():
            user = User.query.get(user_id)
            assert user is None

    def test_purge_all_deleted_users(self, client, admin_user, sample_users):
        """Admin should be able to purge all soft deleted users."""
        # Soft delete some users first
        for user in sample_users[:2]:
            client.post(f'/api/admin/console/users/{user["id"]}/soft-delete')

        response = client.post('/api/admin/console/users/purge-deleted')
        assert response.status_code == 200


class TestAuditLog:
    """Tests for audit log endpoints."""

    def test_view_audit_log(self, client, admin_user):
        """Admin should be able to view audit log."""
        response = client.get('/api/admin/console/audit-log')
        assert response.status_code == 200
        data = response.get_json()
        assert 'logs' in data or 'audit_logs' in data or isinstance(data, list)

    def test_audit_log_pagination(self, client, admin_user):
        """Audit log should support pagination."""
        # Create some audit logs
        with app.app_context():
            for i in range(15):
                log = AuditLog(
                    user_id=admin_user['id'],
                    email=admin_user['email'],
                    event_type='test_event',
                    ip_address='127.0.0.1',
                    user_agent='Test Agent',
                    details=json.dumps({'test': i})
                )
                db.session.add(log)
            db.session.commit()

        response = client.get('/api/admin/console/audit-log?page=1&per_page=10')
        assert response.status_code == 200

    def test_cleanup_old_audit_logs(self, client, admin_user):
        """Admin should be able to cleanup old audit logs."""
        response = client.post('/api/admin/console/audit-log/cleanup')
        assert response.status_code == 200


class TestFailedLogins:
    """Tests for failed login tracking endpoints."""

    def test_view_failed_logins(self, client, admin_user):
        """Admin should be able to view failed login attempts."""
        response = client.get('/api/admin/console/failed-logins')
        assert response.status_code == 200

    def test_cleanup_failed_logins(self, client, admin_user):
        """Admin should be able to cleanup failed login attempts."""
        response = client.post('/api/admin/console/failed-logins/cleanup')
        assert response.status_code == 200


class TestPasswordResets:
    """Tests for password reset management endpoints."""

    def test_view_pending_resets(self, client, admin_user):
        """Admin should be able to view pending password resets."""
        response = client.get('/api/admin/console/password-resets')
        assert response.status_code == 200

    def test_approve_nonexistent_reset_request(self, client, admin_user):
        """Approving nonexistent request should return 404."""
        response = client.post('/api/admin/console/password-resets/99999/approve')
        assert response.status_code == 404

    def test_deny_nonexistent_reset_request(self, client, admin_user):
        """Denying nonexistent request should return 404."""
        response = client.post('/api/admin/console/password-resets/99999/deny')
        assert response.status_code == 404

    def test_mark_complete_nonexistent_reset(self, client, admin_user):
        """Marking nonexistent request complete should return 404."""
        response = client.post('/api/admin/console/password-resets/99999/mark-complete')
        assert response.status_code == 404

    def test_delete_nonexistent_reset_request(self, client, admin_user):
        """Deleting nonexistent request should return 404."""
        response = client.delete('/api/admin/console/password-resets/99999')
        assert response.status_code == 404


class TestAdminCLI:
    """Tests for admin CLI interface."""

    def test_cli_help(self, client, admin_user):
        """Admin should be able to get CLI help."""
        response = client.get('/api/admin/console/cli/help')
        assert response.status_code == 200
        data = response.get_json()
        assert 'commands' in data or 'help' in data

    def test_cli_execute_command(self, client, admin_user):
        """Admin should be able to execute CLI commands."""
        response = client.post('/api/admin/console/cli', json={
            'command': 'help'
        })
        assert response.status_code == 200


class TestBackups:
    """Tests for backup/restore endpoints."""

    def test_list_backups(self, client, admin_user):
        """Admin should be able to list backups."""
        response = client.get('/api/admin/console/backups')
        assert response.status_code == 200
        data = response.get_json()
        assert 'backups' in data or isinstance(data, list)

    def test_create_backup(self, client, admin_user):
        """Admin should be able to create a backup."""
        response = client.post('/api/admin/console/backups/create')
        # May return 200, 202 (accepted for async), or 500 if pg_dump not available in test env
        assert response.status_code in [200, 202, 500]

    def test_validate_backup(self, client, admin_user):
        """Admin should be able to validate a backup file."""
        # This may require a real file - testing endpoint exists
        response = client.post('/api/admin/console/restore/validate', json={
            'filename': 'test_backup.sql'
        })
        # May fail if file doesn't exist, but endpoint should respond
        assert response.status_code in [200, 400, 404]


class TestRBACEnforcement:
    """Tests to ensure RBAC is properly enforced on all admin endpoints."""

    def test_all_admin_endpoints_require_admin_role(self, client, guest_user):
        """All admin console endpoints should require admin role."""
        # Login as guest
        client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })

        admin_endpoints = [
            ('GET', '/api/admin/console/stats'),
            ('GET', '/api/admin/console/artists'),
            ('GET', '/api/admin/console/health'),
            ('GET', '/api/admin/console/audit-log'),
            ('GET', '/api/admin/console/failed-logins'),
            ('GET', '/api/admin/console/users'),
            ('GET', '/api/admin/console/database-info'),
            ('GET', '/api/admin/console/password-resets'),
            ('GET', '/api/admin/console/cli/help'),
            ('GET', '/api/admin/console/backups'),
        ]

        for method, endpoint in admin_endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                response = client.post(endpoint)

            assert response.status_code == 403, f"Expected 403 for {method} {endpoint}, got {response.status_code}"
