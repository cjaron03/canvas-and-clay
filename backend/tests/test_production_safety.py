"""Tests for production safety checks.

These tests verify that the application refuses to start in production mode
without proper security configuration. This is critical to prevent accidental
deployments with missing encryption keys or other security settings.
"""
import os
import subprocess
import sys

import pytest


class TestProductionSecurityRequirements:
    """Tests that verify the app fails fast without proper security config."""

    def test_app_refuses_to_start_without_encryption_key_in_production(self):
        """
        CRITICAL: Verify app crashes in production mode without PII_ENCRYPTION_KEY.

        This test runs a subprocess to import the encryption module with production-like
        environment variables. The module should raise RuntimeError and exit non-zero.
        """
        # Set up a minimal, clean environment (not inheriting from parent)
        # This ensures PII_ENCRYPTION_KEY is truly unset
        env = {
            'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
            'PYTHONPATH': os.path.dirname(os.path.dirname(__file__)),
            'FLASK_ENV': 'production',
            'ALLOW_INSECURE_COOKIES': 'false',
            # Note: PII_ENCRYPTION_KEY is intentionally NOT set
        }

        # Try to import the encryption module - this should fail
        result = subprocess.run(
            [sys.executable, '-c', 'import encryption'],
            cwd=os.path.dirname(os.path.dirname(__file__)),  # backend/
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Module should have failed to load
        assert result.returncode != 0, (
            f"App should refuse to start in production without PII_ENCRYPTION_KEY.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

        # Verify it failed for the right reason
        combined_output = result.stdout + result.stderr
        assert "PII_ENCRYPTION_KEY must be set in production" in combined_output or \
               "RuntimeError" in combined_output, (
            f"App should fail with RuntimeError about missing key.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    def test_app_starts_with_encryption_key_in_production(self):
        """
        Verify app can start in production mode WITH a valid PII_ENCRYPTION_KEY.

        This is the positive test case - with proper configuration, the app
        should initialize without error.
        """
        # Set up a clean production environment with valid key
        env = {
            'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
            'PYTHONPATH': os.path.dirname(os.path.dirname(__file__)),
            'FLASK_ENV': 'production',
            'ALLOW_INSECURE_COOKIES': 'false',
            'PII_ENCRYPTION_KEY': 'valid-encryption-key-32-chars-long',
        }

        # Try to import the encryption module - this should succeed
        result = subprocess.run(
            [sys.executable, '-c', 'from encryption import KEY_SOURCE; print(KEY_SOURCE)'],
            cwd=os.path.dirname(os.path.dirname(__file__)),  # backend/
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Should succeed and show env-key as source
        assert result.returncode == 0, (
            f"App should start with valid PII_ENCRYPTION_KEY.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
        assert "env-key" in result.stdout, (
            f"KEY_SOURCE should be 'env-key' when PII_ENCRYPTION_KEY is set.\n"
            f"stdout: {result.stdout}"
        )

    def test_app_allows_ephemeral_key_in_development(self):
        """
        Verify app starts in development mode without PII_ENCRYPTION_KEY.

        In development mode (FLASK_ENV=development or ALLOW_INSECURE_COOKIES=true),
        the app should allow ephemeral encryption keys for convenience.
        """
        # Set up a clean development environment (no PII_ENCRYPTION_KEY)
        env = {
            'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
            'PYTHONPATH': os.path.dirname(os.path.dirname(__file__)),
            'FLASK_ENV': 'development',
            'ALLOW_INSECURE_COOKIES': 'true',
            # Note: PII_ENCRYPTION_KEY is intentionally NOT set
        }

        # Check KEY_SOURCE - should be ephemeral
        result = subprocess.run(
            [sys.executable, '-c', 'from encryption import KEY_SOURCE; print(KEY_SOURCE)'],
            cwd=os.path.dirname(os.path.dirname(__file__)),  # backend/
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Should succeed with ephemeral key
        assert result.returncode == 0, (
            f"App should start in dev mode without PII_ENCRYPTION_KEY.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
        assert "ephemeral" in result.stdout, (
            f"KEY_SOURCE should be 'ephemeral' when no key is set in dev mode.\n"
            f"stdout: {result.stdout}"
        )

    def test_app_allows_ephemeral_key_in_test_mode(self):
        """
        Verify app starts in test mode without PII_ENCRYPTION_KEY.

        In test mode (FLASK_ENV=testing), ephemeral keys are allowed for CI/CD.
        """
        # Set up a clean test environment
        env = {
            'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
            'PYTHONPATH': os.path.dirname(os.path.dirname(__file__)),
            'FLASK_ENV': 'testing',
            # Note: PII_ENCRYPTION_KEY is intentionally NOT set
        }

        result = subprocess.run(
            [sys.executable, '-c', 'from encryption import KEY_SOURCE; print(KEY_SOURCE)'],
            cwd=os.path.dirname(os.path.dirname(__file__)),  # backend/
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0, (
            f"App should start in test mode without PII_ENCRYPTION_KEY.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
        assert "ephemeral" in result.stdout, (
            f"KEY_SOURCE should be 'ephemeral' in test mode.\n"
            f"stdout: {result.stdout}"
        )
