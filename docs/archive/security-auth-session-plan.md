# Authentication & Session Hardening Plan

**STATUS: COMPLETED - Archived October 27, 2025**

all tasks in this plan have been successfully implemented and merged to main via the `feat/auth-session-hardening` branch. see `README.md` Authentication & Security section for documentation and `backend/tests/test_auth.py` for comprehensive test coverage.

**note:** while the implementation is complete, security audit (in `docs/SECURITY_TODO.md`) identified critical vulnerabilities that need to be addressed before production deployment, including:
- privilege escalation via self-service admin role assignment
- missing csrf protection
- insecure cookie defaults

---

## original plan

Beginning from the latest `main` snapshot, use the steps below to implement two high-priority security items from `docs/SECURITY_TODO.md`.

## Branch Setup
1. `git checkout main`
2. `git pull origin main`
3. `git checkout -b feat/auth-session-hardening`

## Task 1 – User Authentication System
1. **Dependencies**  
   - Add `Flask-Login`, `Flask-Bcrypt`, and `Flask-WTF` to `backend/requirements.txt`.  
   - Run `pip install -r backend/requirements.txt` (or rebuild the Docker image) to sync the environment.
2. **Database Model**  
   - Create a `User` model (`backend/models.py`) with fields for id, email, hashed_password, created_at, role, and remember_token.  
   - Generate and apply Alembic migrations (e.g., `flask db migrate -m "add user model"` / `flask db upgrade`).
3. **Password Management**  
   - Initialize `Bcrypt` in `app.py`.  
   - Hash passwords on registration and verify on login.  
   - Enforce basic password policy (length/complexity) during validation.
4. **Registration Endpoint**  
   - Build `/auth/register` (POST) that validates input (email format, duplicate check, password rules) and persists the new user.  
   - Return success JSON and minimal user metadata (never the hash).  
   - Add pytest coverage for successful registration and duplicate email rejection.
5. **Login Endpoint**  
   - Build `/auth/login` (POST) that checks credentials, returns 401 on failure, and sets the Flask-Login session on success.  
   - Apply rate limiting placeholder (e.g., TODO comment referencing Flask-Limiter) if the dependency isn’t added yet.  
   - Add tests for valid credentials, invalid password, and locked/disabled user behavior (even if stubbed).
6. **Logout Endpoint & Session Teardown**  
   - Implement `/auth/logout` (POST) that requires an authenticated user and calls `logout_user()`.  
   - Add test ensuring sessions are cleared and a 401 is returned when no session exists.
7. **Remember-Me Tokens**  
   - Use Flask-Login’s remember feature; persist tokens in the database.  
   - Ensure tokens are rotated on login/logout.
8. **Route Protection**  
   - Decorate existing protected routes (or create stubs) with `@login_required`.  
   - Add RBAC scaffolding (e.g., role field checks) for future work.

## Task 2 – Secure Session Configuration
1. **Cookie Flags**  
   - In `app.py`, set `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True` (with environment toggle for local dev), and `SESSION_COOKIE_SAMESITE = 'Lax'` or `'Strict'`.  
   - Document local overrides (e.g., `.env`) when HTTPS isn’t available.
2. **Session Lifetime**  
   - Configure `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)` and ensure Flask sessions are permanent only after login.  
   - Force session regeneration on login to prevent fixation (`session.regenerate()` or manual approach).
3. **Remember-Me Duration**  
   - Tune `REMEMBER_COOKIE_DURATION` (e.g., 14 days) and align with Step 7 above.
4. **Blueprint Integration**  
   - Move auth routes into a dedicated blueprint/module to keep session config centralized.  
   - Register the blueprint in `app.py` after configuring sessions.
5. **Middleware & Tests**  
   - Add integration tests to ensure secure cookie flags are present on login responses.  
   - Verify sessions expire as expected by simulating inactivity via configurable clock/test helper.

## Wrap-Up
1. Run automated tests: `pytest backend/tests` (add new suites as needed).  
2. Update documentation (`README.md` and `docs/SECURITY_TODO.md`) with the implemented status and any new env vars.  
3. Review diff, commit, and push:  
   - `git status`  
   - `git commit -am "feat: add auth system and secure session config"`  
   - `git push -u origin feat/auth-session-hardening`
4. Open a pull request summarizing both tasks and referencing `docs/SECURITY_TODO.md`.
