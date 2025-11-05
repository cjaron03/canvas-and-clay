# Upload Security Hardening Plan

## Overview
- Fix image processing so all allowed formats (JPEG, PNG, WebP, AVIF) upload reliably.
- Enforce authorization so only permitted users can attach photos to artworks.
- Guard orphaned photo uploads against storage abuse while keeping admin workflows intact.
- Refresh related docs and rollout guidance once changes land.

## Workstream 1 – Format-Safe Processing
- Branch from `main`, patch `backend/upload_utils.py` so Pillow save options respect the detected MIME type (only set JPEG-specific params when appropriate).
- Extend unit tests to cover processing of each allowed format and assert thumbnails plus metadata persist correctly.
- Run existing integration tests (or `pytest`) to confirm no regressions before merging.

## Workstream 2 – Ownership Enforcement
- Design how artwork ownership maps to user accounts (e.g., join table or explicit foreign key) and align with product requirements.
- Ship the required migration plus model updates (likely in `create_tbls.py` and any ORM models) to capture ownership.
- Update `upload_artwork_photo` to require `current_user` to be the owner or an admin; add tests for authorized and unauthorized uploads.
- Document temporary behavior if ownership data is incomplete (e.g., fall back to admin-only until mapping finishes).

## Workstream 3 – Orphan Upload Controls
- Decide on policy: admin-only, per-user quota, or more aggressive rate limiting for orphaned uploads.
- Implement the chosen guardrail (quota tracking, limiter tweak, or role check) and add logging for attempted overages.
- Verify the limiter behavior with automated tests and manual upload loops to ensure abuse is stopped without blocking valid use.

## Workstream 4 – Documentation & Rollout
- Update `docs/SECURITY_TODO.md` and `docs/TESTING_SECURITY_FIXES.md` with new remediation steps and test instructions.
- Capture migration steps and operational commands (e.g., applying DB migrations, clearing stale thumbnails) in release notes.
- Coordinate deployment: run full test suite, apply migrations, monitor logs for upload errors, and communicate new limits to the team.
