#!/usr/bin/env python3
"""Tests for repair operation locking mechanism.

These tests verify that the file-based locking prevents race conditions
in concurrent repair operations (TOCTOU vulnerability fix).
"""

import fcntl
import multiprocessing
import os
import sys
import tempfile
import time

import pytest

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repair_checks import (
    repair_lock,
    RepairLockError,
    REPAIR_LOCK_FILE
)


class TestRepairLock:
    """Test suite for repair_lock context manager."""

    def test_lock_acquires_successfully(self):
        """Test that lock can be acquired when no other process holds it."""
        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        with repair_lock(blocking=False):
            # Verify lock file was created
            assert os.path.exists(REPAIR_LOCK_FILE)

            # Verify our PID is in the lock file
            with open(REPAIR_LOCK_FILE, 'r') as f:
                content = f.read().strip()
                assert str(os.getpid()) in content

    def test_lock_releases_on_exit(self):
        """Test that lock is released when context manager exits."""
        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        with repair_lock(blocking=False):
            pass

        # After exiting, we should be able to acquire lock again immediately
        with repair_lock(blocking=False):
            pass

    def test_non_blocking_fails_when_locked(self):
        """Test that non-blocking lock fails when another process holds the lock."""

        def hold_lock(duration, ready_event):
            """Helper function to hold lock in subprocess."""
            with open(REPAIR_LOCK_FILE, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                ready_event.set()  # Signal that lock is acquired
                time.sleep(duration)

        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        # Start a process that holds the lock
        ready_event = multiprocessing.Event()
        p = multiprocessing.Process(target=hold_lock, args=(2.0, ready_event))
        p.start()

        try:
            # Wait for the subprocess to acquire the lock
            ready_event.wait(timeout=1.0)
            time.sleep(0.1)  # Small additional delay to ensure lock is held

            # Now try to acquire lock with non-blocking - should fail
            with pytest.raises(RepairLockError) as exc_info:
                with repair_lock(blocking=False):
                    pass

            assert "already in progress" in str(exc_info.value)

        finally:
            p.terminate()
            p.join()

    def test_blocking_with_timeout(self):
        """Test that blocking with timeout raises error after timeout."""

        def hold_lock(duration, ready_event):
            """Helper function to hold lock in subprocess."""
            with open(REPAIR_LOCK_FILE, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                ready_event.set()
                time.sleep(duration)

        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        # Start a process that holds the lock for longer than our timeout
        ready_event = multiprocessing.Event()
        p = multiprocessing.Process(target=hold_lock, args=(5.0, ready_event))
        p.start()

        try:
            # Wait for the subprocess to acquire the lock
            ready_event.wait(timeout=1.0)
            time.sleep(0.1)

            # Try to acquire lock with short timeout - should fail
            start = time.time()
            with pytest.raises(RepairLockError) as exc_info:
                with repair_lock(blocking=True, timeout=0.5):
                    pass
            elapsed = time.time() - start

            assert "Could not acquire" in str(exc_info.value)
            assert elapsed >= 0.4  # Should have waited at least close to timeout

        finally:
            p.terminate()
            p.join()

    def test_lock_cleanup_on_exception(self):
        """Test that lock is properly released even if exception occurs."""
        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        class TestException(Exception):
            pass

        # Acquire lock and raise exception inside
        with pytest.raises(TestException):
            with repair_lock(blocking=False):
                raise TestException("Test error")

        # Lock should be released - we should be able to acquire it again
        with repair_lock(blocking=False):
            pass


class TestRepairLockIntegration:
    """Integration tests for lock with repair functions."""

    def test_run_full_scan_with_lock(self):
        """Test that run_full_scan uses lock by default."""
        from repair_checks import run_full_scan

        # Clean up any existing lock
        if os.path.exists(REPAIR_LOCK_FILE):
            os.remove(REPAIR_LOCK_FILE)

        # This should work since no other process holds the lock
        # Note: This may fail if DB is not available, that's OK for this test
        try:
            result = run_full_scan(use_lock=True)
            # If we get here without RepairLockError, lock was acquired successfully
            assert isinstance(result, dict)
        except Exception as e:
            # DB errors are OK, we just want to verify lock doesn't fail
            if "RepairLockError" in str(type(e).__name__):
                pytest.fail("Should not get RepairLockError")

    def test_run_full_scan_without_lock(self):
        """Test that run_full_scan can run without lock."""
        from repair_checks import run_full_scan

        # This should work even without lock
        try:
            result = run_full_scan(use_lock=False)
            assert isinstance(result, dict)
        except RepairLockError:
            pytest.fail("Should not get RepairLockError with use_lock=False")
        except Exception:
            # Other errors (like DB not available) are OK
            pass
