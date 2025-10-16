import pytest
import sys
import os
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_endpoint(client):
    """Test the home endpoint returns correct response."""
    response = client.get('/')
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'Welcome to Canvas and Clay API'
    assert data['status'] == 'running'

def test_health_endpoint_success(client):
    """Test the health endpoint returns correct response when DB is healthy."""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert data['service'] == 'canvas-clay-backend'
    assert data['database'] == 'connected'

def test_health_endpoint_database_failure(client):
    """Test the health endpoint returns degraded status when DB connection fails."""
    # Mock the database session to raise an exception
    with patch.object(db.session, 'execute') as mock_execute:
        mock_execute.side_effect = Exception('Connection refused')
        
        response = client.get('/health')
        
        # Should return 503 Service Unavailable
        assert response.status_code == 503
        data = response.get_json()
        assert data['status'] == 'degraded'
        assert data['service'] == 'canvas-clay-backend'
        assert 'error' in data['database']
        assert 'Connection refused' in data['database']

def test_security_headers(client):
    """Test that security headers are set on all responses."""
    response = client.get('/')
    
    # Check for required security headers
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('Referrer-Policy') == 'no-referrer'
    assert response.headers.get('Permissions-Policy') == 'geolocation=(), microphone=(), camera=()'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'

def test_security_headers_on_all_endpoints(client):
    """Test that security headers are applied to all endpoints."""
    endpoints = ['/', '/health', '/api/hello']
    
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.headers.get('X-Frame-Options') == 'DENY', f"Missing X-Frame-Options on {endpoint}"
        assert response.headers.get('X-Content-Type-Options') == 'nosniff', f"Missing X-Content-Type-Options on {endpoint}"
        assert response.headers.get('Referrer-Policy') == 'no-referrer', f"Missing Referrer-Policy on {endpoint}"
