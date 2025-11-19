# 2025-10-29 Security Audit

## Overview
- **Scope:** Backend authentication stack (`backend/app.py`, `backend/auth.py`, associated models and tests) plus supporting security documentation.
- **Assessor:** Codex (automated review).
- **Environment:** Repository snapshot on 2025-10-29; dynamic testing not executed because Python dependencies were unavailable locally.

## Key Findings
- **Schema mismatch blocks long emails** – `backend/models.py:33` `backend/models.py:65` `backend/models.py:91` limit email columns to 120 chars, but the API and docs allow 254. In production this raises `DataError` for legitimate addresses, breaking registration, lockout tracking, and audit logging.  
  _Action:_ Expand email column lengths (and migrations) to 254.
- **Logout fails to clear secure cookie** – `backend/auth.py:435` manually expires a `session` cookie without the `Secure` flag. Browsers ignore the deletion cookie when `SESSION_COOKIE_SECURE=True`, leaving sessions active post-logout.  
  _Action:_ Replace with `response.delete_cookie(app.session_cookie_name, secure=..., httponly=True, samesite=...)`.
## Supporting Observations
- Security docs in `docs/TESTING_SECURITY_FIXES.md` assume 254-character emails succeed; once the schema is fixed, keep the doc aligned and add regression coverage.
- Existing automated tests provide good coverage for CSRF, rate limiting, and cookie flags; rerun the suite after applying fixes.

## Recommended Follow-Up
1. Generate and apply migrations for the email column width change; add tests that create/login users at the 254-char boundary.
2. Patch logout to rely on `response.delete_cookie` and verify via browser/dev tools that the secure cookie clears.
3. Update the admin seeding routine to log failures and integrate with deployment health checks.
