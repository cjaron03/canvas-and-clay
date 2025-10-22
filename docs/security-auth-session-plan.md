# authentication & session hardening plan

**status**: phase 1 completed on branch `feat/auth-session-hardening`  
**security grade**: c (needs immediate fixes before production)

beginning from the latest `main` snapshot, use the steps below to implement two high-priority security items from `docs/SECURITY_TODO.md`.

## branch setup
1. ~~`git checkout main`~~ completed
2. ~~`git pull origin main`~~ completed
3. ~~`git checkout -b feat/auth-session-hardening`~~ completed

## task 1 – user authentication system
1. ~~**dependencies**~~ completed
   - ~~add `Flask-Login`, `Flask-Bcrypt`, and `Flask-WTF` to `backend/requirements.txt`~~ completed
   - ~~run `pip install -r backend/requirements.txt` (or rebuild the Docker image) to sync the environment~~ completed
2. ~~**database model**~~ completed
   - ~~create a `User` model (`backend/models.py`) with fields for id, email, hashed_password, created_at, role, and remember_token~~ completed
   - ~~generate and apply Alembic migrations (e.g., `flask db migrate -m "add user model"` / `flask db upgrade`)~~ completed
3. ~~**password management**~~ completed
   - ~~initialize `Bcrypt` in `app.py`~~ completed
   - ~~hash passwords on registration and verify on login~~ completed
   - ~~enforce basic password policy (length/complexity) during validation~~ completed
4. ~~**registration endpoint**~~ completed (CRITICAL ISSUE FOUND)
   - ~~build `/auth/register` (POST) that validates input (email format, duplicate check, password rules) and persists the new user~~ completed
   - ~~return success JSON and minimal user metadata (never the hash)~~ completed
   - ~~add pytest coverage for successful registration and duplicate email rejection~~ completed
5. ~~**login endpoint**~~ completed
   - ~~build `/auth/login` (POST) that checks credentials, returns 401 on failure, and sets the Flask-Login session on success~~ completed
   - ~~apply rate limiting placeholder (e.g., TODO comment referencing Flask-Limiter) if the dependency isn't added yet~~ completed
   - ~~add tests for valid credentials, invalid password, and locked/disabled user behavior (even if stubbed)~~ completed
6. ~~**logout endpoint & session teardown**~~ completed
   - ~~implement `/auth/logout` (POST) that requires an authenticated user and calls `logout_user()`~~ completed
   - ~~add test ensuring sessions are cleared and a 401 is returned when no session exists~~ completed
7. ~~**remember-me tokens**~~ completed
   - ~~use Flask-Login's remember feature; persist tokens in the database~~ completed
   - ~~ensure tokens are rotated on login/logout~~ completed
8. ~~**route protection**~~ completed
   - ~~decorate existing protected routes (or create stubs) with `@login_required`~~ completed
   - ~~add RBAC scaffolding (e.g., role field checks) for future work~~ completed

## task 2 – secure session configuration
1. ~~**cookie flags**~~ completed (CRITICAL ISSUE FOUND)
   - ~~in `app.py`, set `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True` (with environment toggle for local dev), and `SESSION_COOKIE_SAMESITE = 'Lax'` or `'Strict'`~~ completed
   - ~~document local overrides (e.g., `.env`) when HTTPS isn't available~~ completed
2. ~~**session lifetime**~~ completed
   - ~~configure `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)` and ensure Flask sessions are permanent only after login~~ completed
   - ~~force session regeneration on login to prevent fixation (`session.regenerate()` or manual approach)~~ completed
3. ~~**remember-me duration**~~ completed
   - ~~tune `REMEMBER_COOKIE_DURATION` (e.g., 14 days) and align with Step 7 above~~ completed
4. ~~**blueprint integration**~~ completed
   - ~~move auth routes into a dedicated blueprint/module to keep session config centralized~~ completed
   - ~~register the blueprint in `app.py` after configuring sessions~~ completed
5. ~~**middleware & tests**~~ completed
   - ~~add integration tests to ensure secure cookie flags are present on login responses~~ completed
   - ~~verify sessions expire as expected by simulating inactivity via configurable clock/test helper~~ completed

## wrap-up
1. ~~run automated tests: `pytest backend/tests` (add new suites as needed)~~ completed
2. ~~update documentation (`README.md` and `docs/SECURITY_TODO.md`) with the implemented status and any new env vars~~ completed
3. ~~review diff, commit, and push~~ completed
4. ~~open a pull request summarizing both tasks and referencing `docs/SECURITY_TODO.md`~~ completed

---

## critical security issues discovered

### CRITICAL: privilege escalation via self-service admin role
**location**: `backend/auth.py:96-142`  
**issue**: registration endpoint trusts client-supplied role parameter. anyone can sign up and pass `"role": "admin"` to get full admin access.  
**impact**: immediate privilege escalation path. any user can become admin.  
**fix required**: 
- remove role parameter from registration endpoint
- force all new users to 'visitor' role
- add separate admin promotion endpoint that requires existing admin authentication
- add server-side role assignment logic

### CRITICAL: csrf protection missing
**location**: `backend/app.py:86-88`, `backend/auth.py:72-210`  
**issue**: session-based auth endpoints ship without CSRF defenses. Flask-WTF installed but not configured. once SPA and API run on same origin, malicious sites can ride user's browser to issue authenticated requests.  
**impact**: attackers can perform actions as authenticated users via CSRF attacks.  
**fix required**:
- enable Flask-WTF CSRF protection
- add CSRF tokens to all POST/PUT/DELETE requests
- configure CSRF exemptions only for truly stateless API endpoints
- add CSRF token to frontend forms

### CRITICAL: insecure cookie defaults for production
**location**: `backend/app.py:25-33`  
**issue**: `SESSION_COOKIE_SECURE` and `REMEMBER_COOKIE_SECURE` default to False. unless env var is overridden in prod, cookies ride over plain HTTP, exposing session/remember tokens.  
**impact**: session hijacking via man-in-the-middle attacks.  
**fix required**:
- flip defaults so cookies are secure by default
- require explicit opt-out for local development only
- add startup validation to fail if secure cookies disabled in production
- document environment-based configuration clearly

### major: information disclosure in error responses
**location**: `backend/auth.py:132-148`  
**issue**: when registration fails, code echoes `str(e)` back to client. leaks raw database or stack details that attackers can use for reconnaissance.  
**impact**: database schema exposure, potential SQL injection vectors revealed.  
**fix required**:
- replace `str(e)` in responses with generic error messages
- log detailed errors server-side only
- implement proper error handling with user-safe messages
- add structured logging for security events

### major: rate limiting not implemented
**location**: `backend/auth.py:149-212` (login endpoint)  
**issue**: login endpoint has TODO comment for rate limiting but not implemented. unlimited login attempts possible.  
**impact**: brute force attacks, credential stuffing, account enumeration.  
**fix required**:
- add Flask-Limiter to requirements
- implement rate limiting: 5 attempts per minute per IP on /auth/login
- add account lockout after 5 failed attempts (15 minute lockout)
- log failed login attempts for security monitoring

### major: hardcoded cors origins
**location**: `backend/app.py:14-17`  
**issue**: CORS origins hardcoded to `http://localhost:5173`, won't work in production.  
**impact**: application breaks in production or opens up to all origins if wildcard used.  
**fix required**:
- move CORS origins to environment variable
- support multiple origins (dev, staging, prod)
- validate origins before starting server
- document required environment configuration

### medium: no input length validation
**location**: `backend/auth.py:96-142`  
**issue**: email and password inputs have no maximum length validation. database columns have limits but not enforced in code.  
**impact**: potential DoS via extremely long inputs, database errors.  
**fix required**:
- add max length validation: email <= 254 chars, password <= 128 chars
- validate before database operations
- return clear error messages for length violations

### medium: no account lockout mechanism
**location**: entire auth system  
**issue**: no protection against repeated failed login attempts on same account.  
**impact**: brute force attacks on individual accounts.  
**fix required**:
- track failed login attempts per account
- lock account after 5 failed attempts
- implement time-based unlock (15 minutes) or admin unlock
- notify user of account lockout via email

### medium: no audit logging
**location**: entire auth system  
**issue**: no logging of security events (logins, role changes, failed attempts, etc).  
**impact**: cannot detect or investigate security breaches.  
**fix required**:
- implement structured audit logging
- log all authentication events (success and failure)
- log sensitive operations (role changes, password resets)
- include IP address, user agent, timestamp in logs
- set up log aggregation and alerting

---

## security assessment

**overall grade**: c  
**strengths**: bcrypt password hashing, Flask-Login integration, basic input validation, session management foundation  
**weaknesses**: self-service admin creation, missing CSRF protection, insecure cookie defaults, information disclosure

**must fix before production**:
1. privilege escalation (admin role assignment)
2. CSRF protection
3. secure cookie defaults
4. error information disclosure
5. rate limiting and account lockout
