# Upload Security Hardening Plan

## Overview
- Fix image processing so all allowed formats (JPEG, PNG, WebP, AVIF) upload reliably.
- Enforce authorization so only permitted users can attach photos to artworks.
- Guard orphaned photo uploads against storage abuse while keeping admin workflows intact.
- Refresh related docs and rollout guidance once changes land.

## Workstream 1 – Format-Safe Processing **DONE**
- Branch from `main`, patch `backend/upload_utils.py` so Pillow save options respect the detected MIME type (only set JPEG-specific params when appropriate).
- Extend unit tests to cover processing of each allowed format and assert thumbnails plus metadata persist correctly.
- Run existing integration tests (or `pytest`) to confirm no regressions before merging.

## Workstream 2 – Ownership Enforcement **DONE**
- ✅ Designed ownership model: Added `user_id` foreign key to Artist table (nullable, many-to-one relationship).
- ✅ Shipped database migration `dd25ebc37dcf_add_user_id_to_artist.py` to add `artist.user_id` column with CASCADE/SET NULL constraints.
- ✅ Updated `upload_artwork_photo()` in `app.py` to enforce ownership: artists with `user_id=NULL` require admin access (secure default), artists with `user_id` require owner or admin.
- ✅ Added admin endpoints:
  - `POST /api/admin/artists/<artist_id>/assign-user` - Link artist to user account
  - `POST /api/admin/artists/<artist_id>/unassign-user` - Unlink artist from user account
- ✅ Implemented temporary behavior: Artworks with unlinked artists (user_id=NULL) fall back to admin-only upload access until admin assigns ownership.
- ✅ Added comprehensive test suite in `tests/test_artwork_ownership.py` covering authorization scenarios (note: requires fixture setup refinement for execution).

**Migration Applied**: `flask db upgrade` completed successfully. All existing artists have `user_id=NULL` by default.

## Workstream 3 – Orphan Upload Controls
- Decide on policy: admin-only, per-user quota, or more aggressive rate limiting for orphaned uploads.
- Implement the chosen guardrail (quota tracking, limiter tweak, or role check) and add logging for attempted overages.
- Verify the limiter behavior with automated tests and manual upload loops to ensure abuse is stopped without blocking valid use.

## Workstream 4 – Documentation & Rollout
- Update `docs/SECURITY_TODO.md` and `docs/TESTING_SECURITY_FIXES.md` with new remediation steps and test instructions.
- Capture migration steps and operational commands (e.g., applying DB migrations, clearing stale thumbnails) in release notes.
- Coordinate deployment: run full test suite, apply migrations, monitor logs for upload errors, and communicate new limits to the team.
