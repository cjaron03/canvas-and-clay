"""Tests for artist email duplicate detection logic in migration.

This module tests the duplicate email detection logic used in the
add_artist_email_blind_index migration. The migration needs to detect
duplicate artist emails (based on normalized blind index) before applying
a unique constraint.

Tests cover:
1. Three or more artists sharing the same email
2. Multiple different duplicate email groups
3. Email masking for PII protection
4. No duplicates case (clean migration)
5. Mixed case normalized duplicates (case-insensitive detection)
"""

import os
import sys
import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up test environment before importing encryption module
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-duplicate-detection-tests')
os.environ.setdefault('FLASK_ENV', 'development')

from encryption import compute_blind_index, normalize_email


def group_by_blind_index(artists_data):
    """Group artists by their blind index.

    This mirrors the logic in the migration that groups artists
    by their computed blind index to detect duplicates.

    Args:
        artists_data: List of dicts with 'id', 'email' keys

    Returns:
        Dict mapping blind_index -> list of artist dicts with 'id', 'email', 'idx'
    """
    index_groups = {}
    for artist in artists_data:
        email = artist['email']
        if email is None:
            continue
        idx = compute_blind_index(email, normalizer=normalize_email)
        if idx not in index_groups:
            index_groups[idx] = []
        index_groups[idx].append({
            'id': artist['id'],
            'email': email,
            'idx': idx
        })
    return index_groups


def find_duplicates(index_groups):
    """Find groups with more than one artist (duplicates).

    Mirrors the migration logic that detects duplicate emails
    before applying the unique constraint.

    Args:
        index_groups: Dict from group_by_blind_index()

    Returns:
        List of tuples: (email, [artist_ids])
    """
    duplicates = []
    for idx, artists in index_groups.items():
        if len(artists) > 1:
            # Use the first artist's email as representative
            email = artists[0]['email']
            artist_ids = [a['id'] for a in artists]
            duplicates.append((email, artist_ids))
    return duplicates


def mask_email(email):
    """Mask email for PII protection.

    Mirrors the migration's email masking logic to prevent
    exposing full PII in error messages.

    Args:
        email: Raw email string

    Returns:
        Masked email (e.g., 'john@example.com' -> 'j***@example.com')
    """
    if '@' in email:
        local, domain = email.split('@', 1)
        masked_local = local[0] + '***' if len(local) > 0 else '***'
        return f"{masked_local}@{domain}"
    return '***'


def format_duplicate_lines(duplicates):
    """Format duplicates for error message.

    Mirrors the migration's formatting logic for the error output.

    Args:
        duplicates: List from find_duplicates()

    Returns:
        List of formatted strings
    """
    dup_lines = []
    for email, artist_ids in duplicates:
        dup_lines.append(f"  - '{mask_email(email)}' used by artist IDs: {artist_ids}")
    return dup_lines


class TestMaskEmail:
    """Tests for email masking (PII protection)."""

    def test_mask_simple_email(self):
        """Basic email masking should preserve first char and domain."""
        result = mask_email("john@example.com")
        assert result == "j***@example.com"

    def test_mask_short_local_part(self):
        """Single character local part should still mask properly."""
        result = mask_email("j@example.com")
        assert result == "j***@example.com"

    def test_mask_long_local_part(self):
        """Long local part should mask all but first char."""
        result = mask_email("verylonglocalpart@example.com")
        assert result == "v***@example.com"

    def test_mask_preserves_full_domain(self):
        """Domain should be fully preserved including subdomains."""
        result = mask_email("user@subdomain.example.co.uk")
        assert result == "u***@subdomain.example.co.uk"

    def test_mask_with_special_characters_in_local(self):
        """Special characters in local part should be masked."""
        result = mask_email("user.name+tag@example.com")
        assert result == "u***@example.com"

    def test_mask_no_at_symbol(self):
        """Invalid email without @ should return '***'."""
        result = mask_email("notanemail")
        assert result == "***"

    def test_mask_empty_local_part(self):
        """Email with empty local part should handle edge case."""
        # Edge case: @domain.com (technically invalid but we handle it)
        result = mask_email("@example.com")
        # Empty string has len 0, so condition `len(local) > 0` is False
        assert result == "***@example.com"


class TestGroupByBlindIndex:
    """Tests for grouping artists by blind index."""

    def test_groups_identical_emails(self):
        """Artists with identical emails should be in same group."""
        artists = [
            {'id': 'ART001', 'email': 'shared@example.com'},
            {'id': 'ART002', 'email': 'shared@example.com'},
        ]
        groups = group_by_blind_index(artists)
        # Should have exactly one group
        assert len(groups) == 1
        # Group should contain both artists
        group = list(groups.values())[0]
        assert len(group) == 2
        ids = [a['id'] for a in group]
        assert 'ART001' in ids
        assert 'ART002' in ids

    def test_groups_unique_emails_separately(self):
        """Artists with unique emails should be in separate groups."""
        artists = [
            {'id': 'ART001', 'email': 'user1@example.com'},
            {'id': 'ART002', 'email': 'user2@example.com'},
            {'id': 'ART003', 'email': 'user3@example.com'},
        ]
        groups = group_by_blind_index(artists)
        # Should have three separate groups
        assert len(groups) == 3
        # Each group should have exactly one artist
        for group in groups.values():
            assert len(group) == 1

    def test_handles_null_emails(self):
        """Null emails should be skipped (not grouped)."""
        artists = [
            {'id': 'ART001', 'email': None},
            {'id': 'ART002', 'email': 'user@example.com'},
            {'id': 'ART003', 'email': None},
        ]
        groups = group_by_blind_index(artists)
        # Only one non-null email, so one group
        assert len(groups) == 1
        group = list(groups.values())[0]
        assert len(group) == 1
        assert group[0]['id'] == 'ART002'

    def test_normalizes_case_for_grouping(self):
        """Different case emails should be grouped together (normalized)."""
        artists = [
            {'id': 'ART001', 'email': 'User@Example.COM'},
            {'id': 'ART002', 'email': 'user@example.com'},
            {'id': 'ART003', 'email': 'USER@EXAMPLE.COM'},
        ]
        groups = group_by_blind_index(artists)
        # All should be in same group after normalization
        assert len(groups) == 1
        group = list(groups.values())[0]
        assert len(group) == 3

    def test_normalizes_whitespace_for_grouping(self):
        """Emails with leading/trailing whitespace should be grouped together."""
        artists = [
            {'id': 'ART001', 'email': '  user@example.com'},
            {'id': 'ART002', 'email': 'user@example.com  '},
            {'id': 'ART003', 'email': '  user@example.com  '},
        ]
        groups = group_by_blind_index(artists)
        # All should be in same group after normalization
        assert len(groups) == 1
        group = list(groups.values())[0]
        assert len(group) == 3


class TestFindDuplicates:
    """Tests for finding duplicate email groups."""

    def test_no_duplicates_returns_empty(self):
        """When no duplicates exist, should return empty list."""
        artists = [
            {'id': 'ART001', 'email': 'user1@example.com'},
            {'id': 'ART002', 'email': 'user2@example.com'},
            {'id': 'ART003', 'email': 'user3@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert duplicates == []

    def test_finds_two_artists_sharing_email(self):
        """Should detect when two artists share an email."""
        artists = [
            {'id': 'ART001', 'email': 'shared@example.com'},
            {'id': 'ART002', 'email': 'shared@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        assert 'ART001' in artist_ids
        assert 'ART002' in artist_ids

    def test_finds_three_artists_sharing_email(self):
        """Should detect when three artists share an email (all IDs reported)."""
        artists = [
            {'id': 'ART001', 'email': 'shared@example.com'},
            {'id': 'ART002', 'email': 'shared@example.com'},
            {'id': 'ART003', 'email': 'shared@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        assert len(artist_ids) == 3
        assert 'ART001' in artist_ids
        assert 'ART002' in artist_ids
        assert 'ART003' in artist_ids

    def test_finds_five_artists_sharing_email(self):
        """Should detect when many artists share an email."""
        artists = [
            {'id': f'ART00{i}', 'email': 'shared@example.com'}
            for i in range(1, 6)
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        assert len(artist_ids) == 5

    def test_finds_multiple_duplicate_groups(self):
        """Should detect multiple different duplicate email groups."""
        artists = [
            # Group A: 2 artists share email A
            {'id': 'ART001', 'email': 'shared-a@example.com'},
            {'id': 'ART002', 'email': 'shared-a@example.com'},
            # Group B: 3 artists share email B
            {'id': 'ART003', 'email': 'shared-b@example.com'},
            {'id': 'ART004', 'email': 'shared-b@example.com'},
            {'id': 'ART005', 'email': 'shared-b@example.com'},
            # Unique email (not a duplicate)
            {'id': 'ART006', 'email': 'unique@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        # Should find 2 duplicate groups
        assert len(duplicates) == 2

        # Check that both groups are reported correctly
        duplicate_emails = {normalize_email(dup[0]) for dup in duplicates}
        assert 'shared-a@example.com' in duplicate_emails
        assert 'shared-b@example.com' in duplicate_emails

        # Verify artist counts per group
        for email, artist_ids in duplicates:
            if normalize_email(email) == 'shared-a@example.com':
                assert len(artist_ids) == 2
            elif normalize_email(email) == 'shared-b@example.com':
                assert len(artist_ids) == 3

    def test_excludes_unique_emails_from_duplicates(self):
        """Unique emails should not appear in duplicates list."""
        artists = [
            {'id': 'ART001', 'email': 'shared@example.com'},
            {'id': 'ART002', 'email': 'shared@example.com'},
            {'id': 'ART003', 'email': 'unique@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        # The unique email should not be in any duplicate group
        assert 'ART003' not in artist_ids


class TestMixedCaseNormalization:
    """Tests for case-insensitive duplicate detection."""

    def test_detects_mixed_case_duplicates(self):
        """Different case versions of same email should be detected as duplicates."""
        artists = [
            {'id': 'ART001', 'email': 'User@Example.com'},
            {'id': 'ART002', 'email': 'user@example.com'},
            {'id': 'ART003', 'email': 'USER@EXAMPLE.COM'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        assert len(artist_ids) == 3

    def test_different_emails_not_detected_as_duplicates(self):
        """Emails that differ only by domain should not be duplicates."""
        artists = [
            {'id': 'ART001', 'email': 'user@example.com'},
            {'id': 'ART002', 'email': 'user@example.org'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        assert len(duplicates) == 0

    def test_whitespace_variations_detected_as_duplicates(self):
        """Emails with whitespace variations should be detected as duplicates."""
        artists = [
            {'id': 'ART001', 'email': 'user@example.com'},
            {'id': 'ART002', 'email': '  user@example.com'},
            {'id': 'ART003', 'email': 'user@example.com  '},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        assert len(duplicates) == 1
        email, artist_ids = duplicates[0]
        assert len(artist_ids) == 3


class TestFormatDuplicateLines:
    """Tests for formatting duplicate output lines."""

    def test_formats_single_duplicate_group(self):
        """Single duplicate group should be formatted correctly."""
        duplicates = [
            ('john@example.com', ['ART001', 'ART002'])
        ]
        lines = format_duplicate_lines(duplicates)

        assert len(lines) == 1
        assert "j***@example.com" in lines[0]
        assert "ART001" in lines[0]
        assert "ART002" in lines[0]

    def test_formats_multiple_duplicate_groups(self):
        """Multiple duplicate groups should each have their own line."""
        duplicates = [
            ('user-a@example.com', ['ART001', 'ART002']),
            ('user-b@example.com', ['ART003', 'ART004', 'ART005']),
        ]
        lines = format_duplicate_lines(duplicates)

        assert len(lines) == 2

    def test_masks_email_in_output(self):
        """Email should be masked in output (PII protection)."""
        duplicates = [
            ('sensitiveuser@company.com', ['ART001', 'ART002'])
        ]
        lines = format_duplicate_lines(duplicates)

        assert len(lines) == 1
        # Full email should NOT appear
        assert 'sensitiveuser@company.com' not in lines[0]
        # Masked email should appear
        assert 's***@company.com' in lines[0]

    def test_includes_all_artist_ids(self):
        """All artist IDs should be included in output."""
        duplicates = [
            ('shared@example.com', ['ART001', 'ART002', 'ART003', 'ART004', 'ART005'])
        ]
        lines = format_duplicate_lines(duplicates)

        for artist_id in ['ART001', 'ART002', 'ART003', 'ART004', 'ART005']:
            assert artist_id in lines[0]


class TestBlindIndexConsistency:
    """Tests to verify blind index behavior for duplicate detection."""

    def test_blind_index_deterministic(self):
        """Same email should always produce same blind index."""
        email = "test@example.com"
        idx1 = compute_blind_index(email, normalizer=normalize_email)
        idx2 = compute_blind_index(email, normalizer=normalize_email)
        assert idx1 == idx2

    def test_blind_index_length(self):
        """Blind index should be 64 character hex string."""
        email = "test@example.com"
        idx = compute_blind_index(email, normalizer=normalize_email)
        assert len(idx) == 64
        # Verify it's valid hex
        int(idx, 16)

    def test_normalized_emails_same_index(self):
        """Normalized emails should produce identical blind indexes."""
        emails = [
            "User@Example.COM",
            "user@example.com",
            "  user@example.com  ",
            "USER@EXAMPLE.COM",
        ]
        indexes = [compute_blind_index(e, normalizer=normalize_email) for e in emails]
        # All should be the same
        assert all(idx == indexes[0] for idx in indexes)

    def test_different_emails_different_index(self):
        """Different emails should produce different blind indexes."""
        idx1 = compute_blind_index("user1@example.com", normalizer=normalize_email)
        idx2 = compute_blind_index("user2@example.com", normalizer=normalize_email)
        assert idx1 != idx2


class TestEdgeCases:
    """Tests for edge cases in duplicate detection."""

    def test_empty_artist_list(self):
        """Empty artist list should produce no duplicates."""
        groups = group_by_blind_index([])
        duplicates = find_duplicates(groups)
        assert duplicates == []

    def test_all_null_emails(self):
        """All null emails should produce no duplicates."""
        artists = [
            {'id': 'ART001', 'email': None},
            {'id': 'ART002', 'email': None},
            {'id': 'ART003', 'email': None},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert duplicates == []

    def test_single_artist_not_duplicate(self):
        """Single artist should not be reported as duplicate."""
        artists = [
            {'id': 'ART001', 'email': 'solo@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert duplicates == []

    def test_many_artists_all_unique(self):
        """Many artists with unique emails should have no duplicates."""
        artists = [
            {'id': f'ART{str(i).zfill(3)}', 'email': f'user{i}@example.com'}
            for i in range(100)
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert duplicates == []

    def test_special_characters_in_email(self):
        """Emails with special characters should be handled correctly."""
        artists = [
            {'id': 'ART001', 'email': 'user+tag@example.com'},
            {'id': 'ART002', 'email': 'user+tag@example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert len(duplicates) == 1

    def test_subdomain_in_email(self):
        """Emails with subdomains should be handled correctly."""
        artists = [
            {'id': 'ART001', 'email': 'user@mail.subdomain.example.com'},
            {'id': 'ART002', 'email': 'user@mail.subdomain.example.com'},
        ]
        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        assert len(duplicates) == 1


class TestIntegrationScenarios:
    """Integration tests simulating realistic migration scenarios."""

    def test_realistic_duplicate_scenario(self):
        """Simulate a realistic dataset with some duplicates."""
        # Scenario: Small gallery with 20 artists, 3 duplicate situations
        artists = [
            # 10 unique artists
            {'id': 'ART00001', 'email': 'alice@gallery.com'},
            {'id': 'ART00002', 'email': 'bob@gallery.com'},
            {'id': 'ART00003', 'email': 'charlie@gallery.com'},
            {'id': 'ART00004', 'email': 'diana@gallery.com'},
            {'id': 'ART00005', 'email': 'edward@gallery.com'},
            {'id': 'ART00006', 'email': 'fiona@gallery.com'},
            {'id': 'ART00007', 'email': 'george@gallery.com'},
            {'id': 'ART00008', 'email': 'helen@gallery.com'},
            {'id': 'ART00009', 'email': None},  # No email
            {'id': 'ART00010', 'email': None},  # No email

            # Duplicate group 1: Married couple using same email (2 artists)
            {'id': 'ART00011', 'email': 'smith-family@home.com'},
            {'id': 'ART00012', 'email': 'smith-family@home.com'},

            # Duplicate group 2: Art collective (4 artists, same email)
            {'id': 'ART00013', 'email': 'collective@art.org'},
            {'id': 'ART00014', 'email': 'COLLECTIVE@ART.ORG'},  # Different case
            {'id': 'ART00015', 'email': '  collective@art.org  '},  # Whitespace
            {'id': 'ART00016', 'email': 'Collective@Art.Org'},  # Mixed case

            # Duplicate group 3: Typo introduced duplicate (3 artists)
            {'id': 'ART00017', 'email': 'johnson@studio.com'},
            {'id': 'ART00018', 'email': 'Johnson@Studio.com'},  # Case variation
            {'id': 'ART00019', 'email': 'johnson@studio.com'},  # Exact duplicate

            # One more unique
            {'id': 'ART00020', 'email': 'independent@artist.io'},
        ]

        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        # Should find exactly 3 duplicate groups
        assert len(duplicates) == 3

        # Verify each group has correct count
        for email, artist_ids in duplicates:
            normalized = normalize_email(email)
            if normalized == 'smith-family@home.com':
                assert len(artist_ids) == 2
            elif normalized == 'collective@art.org':
                assert len(artist_ids) == 4
            elif normalized == 'johnson@studio.com':
                assert len(artist_ids) == 3

    def test_clean_migration_no_duplicates(self):
        """Simulate a clean migration with no duplicates."""
        artists = [
            {'id': f'ART{str(i).zfill(5)}', 'email': f'artist{i}@gallery.com'}
            for i in range(50)
        ]
        # Add some with no email
        artists.extend([
            {'id': 'ART00051', 'email': None},
            {'id': 'ART00052', 'email': None},
        ])

        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)

        # Should find no duplicates
        assert len(duplicates) == 0
        # Verify all 50 emails are in separate groups
        assert len(groups) == 50

    def test_error_message_format(self):
        """Verify the complete error message format matches migration output."""
        artists = [
            {'id': 'ART001', 'email': 'duplicate@test.com'},
            {'id': 'ART002', 'email': 'duplicate@test.com'},
            {'id': 'ART003', 'email': 'duplicate@test.com'},
        ]

        groups = group_by_blind_index(artists)
        duplicates = find_duplicates(groups)
        dup_lines = format_duplicate_lines(duplicates)

        # Verify format matches migration's expected output
        assert len(dup_lines) == 1
        line = dup_lines[0]

        # Should start with indentation
        assert line.startswith("  - ")
        # Should contain masked email
        assert "d***@test.com" in line
        # Should list all artist IDs
        assert "ART001" in line
        assert "ART002" in line
        assert "ART003" in line
        # Should use the format "used by artist IDs:"
        assert "used by artist IDs:" in line
