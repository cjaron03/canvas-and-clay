# Security Implementation TODO List For JC

## current sprint plan (phase 2 - security hardening)

### immediate priorities (critical fixes)
1. **fix privilege escalation** - remove client-controlled role assignment in registration
2. **fix insecure cookie defaults** - flip SESSION_COOKIE_SECURE to true by default
3. **fix information disclosure** - remove str(e) from error responses
4. **add csrf protection** - enable Flask-WTF, add tokens to all state-changing requests
5. **enable rate limiting** - uncomment Flask-Limiter, add to login/register endpoints
6. **fix hardcoded cors origins** - move to environment variables for prod deployment
7. **build authentication UI** - login/register forms in SvelteKit

### secondary priorities (major issues)
- account lockout mechanism after failed login attempts
- audit logging for security events
- input length validation to prevent dos attacks

### scaffolding status

**ready to implement (scaffolding exists):**
- csrf protection - Flask-WTF already installed, tests already disable it, TODOs marked (~45-60 min)
- rate limiting - Flask-Limiter commented out in requirements.txt, ready to uncomment (~30 min)
- authentication system - fully built (login/logout/register, password hashing, sessions, RBAC)

**requires building from scratch (no scaffolding):**
- two-factor authentication (2FA) - no TOTP library, no database fields, starting from scratch
- JWT tokens - PyJWT commented out, would need refactoring from session-based auth
- file upload security - no endpoints, no validation libraries, no virus scanning
- penetration testing - no tooling, manual security testing work
- audit logging - no structured logging infrastructure beyond Flask defaults

---

## Security Audit Results (October 2025)

### authentication system implemented but critical vulnerabilities found

### CRITICAL - must fix before production
- [x] **privilege escalation via self-service admin role** - FIXED (fix-privilege-escalation-csrf branch)
  - removed role parameter from registration endpoint
  - all new users are forced to 'visitor' role
  - admin promotion endpoint deferred to future implementation

- [x] **csrf protection missing** - FIXED (fix-privilege-escalation-csrf branch)
  - Flask-WTF CSRF protection enabled globally
  - added `/auth/csrf-token` endpoint for frontend to fetch tokens
  - csrf tokens required in X-CSRFToken header for all POST/PUT/DELETE requests
  - comprehensive csrf tests added to test suite

- [x] **insecure cookie defaults** - FIXED (fix-cookie-cors-input-validation branch)
  - SESSION_COOKIE_SECURE and REMEMBER_COOKIE_SECURE now default to True
  - cookies require HTTPS by default, explicit opt-out via ALLOW_INSECURE_COOKIES env var for local dev
  - startup validation added to warn about insecure configuration

- [x] **information disclosure in error responses** - FIXED (fix-privilege-escalation-csrf branch)
  - registration failures now return generic 'Failed to create user' message
  - internal error details no longer exposed to client
  - detailed errors should be logged server-side only

### major issues
- [x] **rate limiting not implemented** - FIXED (fix-privilege-escalation-csrf branch)
  - Flask-Limiter added to requirements.txt
  - rate limiting applied to login endpoint (5 attempts per 15 min per IP)
  - IP-based rate limiting prevents brute force attacks
- [x] **hardcoded cors origins** - FIXED (fix-cookie-cors-input-validation branch)
  - CORS origins moved to CORS_ORIGINS environment variable
  - supports multiple origins separated by commas
  - defaults to http://localhost:5173 for backward compatibility
- [x] **no account lockout mechanism** - FIXED (fix-privilege-escalation-csrf branch)
  - account lockout after 5 failed attempts (15 min lockout period)
  - failed login attempts tracked in database
  - lockout clears automatically after 15 minutes
- [x] **no audit logging** - FIXED (fix-privilege-escalation-csrf branch)
  - structured audit logging implemented
  - all login attempts logged (success and failure)
  - failed login attempts logged with IP address and user agent
  - account lockout events logged
  - rate limit exceeded events logged

### completed in feat/auth-session-hardening branch
- [x] user authentication system with registration, login, and logout
- [x] bcrypt password hashing with strong password requirements
- [x] secure session management with HttpOnly, Secure, and SameSite cookies (defaults need fixing)
- [x] role-based access control (RBAC) with @login_required and @admin_required decorators (role assignment broken)
- [x] remember-me functionality with secure token management
- [x] comprehensive test suite for authentication and session security
- [x] api input validation for authentication endpoints (needs length limits)

see the Authentication & Security section in README.md for full details.

---

## Upload Security Implementation (November 2025)

### comprehensive file upload hardening completed

### workstream 1 - format-safe processing
- [x] **format-specific save options** - COMPLETED
  - implemented `get_save_options()` in `upload_utils.py` to respect detected MIME types
  - JPEG: quality=95, optimize=True, progressive=True
  - PNG: optimize=True, compress_level=6 (lossless)
  - WebP: quality=90, method=6
  - AVIF: quality=80 (excellent compression)
  - prevents errors when JPEG params applied to PNG/WebP/AVIF files
  - comprehensive test coverage for all formats in `test_upload_utils.py`

### workstream 2 - ownership enforcement
- [x] **artist-user linking** - COMPLETED
  - added `user_id` column to Artist table (nullable, FK to users with CASCADE/SET NULL)
  - migration `dd25ebc37dcf_add_user_id_to_artist.py` successfully applied
  - secure default: artists with `user_id=NULL` require admin access for photo uploads
  - ownership: artists with `user_id` require owner or admin for photo uploads
  - prevents unauthorized photo uploads to other users' artworks

- [x] **admin artist management endpoints** - COMPLETED
  - `POST /api/admin/artists/<id>/assign-user` - link artist to user account
  - `POST /api/admin/artists/<id>/unassign-user` - unlink artist from user account
  - comprehensive test coverage in `test_artwork_ownership.py`

### workstream 3 - orphaned upload controls
- [x] **admin-only policy** - COMPLETED
  - orphaned uploads (`POST /api/photos`) now require admin role
  - prevents storage abuse by regular users
  - regular users must associate photos with artworks they own
  - rate limited to 20 per minute per IP
  - comprehensive test coverage for admin/user/unauthenticated access scenarios

### implementation details
- **upload endpoint**: `POST /api/artworks/<id>/photos` (owner or admin)
- **orphaned endpoint**: `POST /api/photos` (admin only)
- **security validations**: magic bytes, file size (10MB max), image dimensions (8000x8000 max), filename sanitization
- **image processing**: re-encoding strips EXIF/metadata, thumbnail generation, format-appropriate compression
- **authorization flow**:
  1. check artwork exists
  2. check artist ownership (user_id matches current_user.id or user is admin)
  3. fallback: artist with no user_id requires admin access (secure default)

see `docs/UPLOAD_SECURITY_PLAN.md` for complete implementation details and test results.

---

## RBAC & Dynamic Rate Limiting (November 2025)

### role normalization and identity-based rate limiting completed

### phase 1 - role normalization (visitor → guest)
- [x] **semantic improvement** - COMPLETED
  - normalized role from 'visitor' to 'guest' for clarity
  - `User.normalized_role` property handles backwards compatibility
  - `User.is_guest` property added for convenience
  - database migration updates existing 'visitor' roles to 'guest'
  - code fallback treats legacy 'visitor' as 'guest'
  - all API responses now return normalized roles
  - tests updated to expect 'guest' instead of 'visitor'

### phase 2 - dynamic rate limiting by identity
- [x] **identity-based rate limits** - COMPLETED
  - `get_rate_limit_by_identity()` function determines rate limit dynamically
  - anonymous users (no session): 100 requests/minute
  - logged-in guests (including artist-linked): 200 requests/minute
  - admins: 1000 requests/minute
  - upload endpoints: 20/minute for ALL users (security-critical)
  - applied to public read endpoints (search, browse, view)

### phase 3 - RBAC decorators and helpers
- [x] **helper functions** - COMPLETED
  - `get_current_role()` - returns 'admin', 'guest', or 'anonymous'
  - `is_artwork_owner(artwork)` - checks `artwork.artist.user_id == current_user.id`
  - `is_photo_owner(photo)` - checks artwork ownership via photo's artwork
  - `log_rbac_denial(resource_type, resource_id, reason)` - audit logs with differentiated reasons

### phase 4 - ownership-based mutation permissions
- [x] **endpoint permissions** - COMPLETED
  - **public read (anonymous/guest)**: search, browse artworks, view details
  - **owner OR admin**: edit/delete artwork, upload/delete photos on owned artworks
  - **admin-only**: create artworks, orphaned photo uploads, storage CRUD, artist-user assignment
  - owners can delete ANY photo on their artwork (not just photos they uploaded)
  - consistent 403 responses with differentiated audit logging

### implementation details
- **permission matrix**:
  | Action              | Guest | Guest+Owner | Admin |
  |---------------------|-------|-------------|-------|
  | Search/browse       | ✓     | ✓           | ✓     |
  | Create artwork      | ✗     | ✗           | ✓     |
  | Edit own artwork    | ✗     | ✓           | ✓     |
  | Delete own artwork  | ✗     | ✓           | ✓     |
  | Upload to own art   | ✗     | ✓           | ✓     |
  | Upload orphaned     | ✗     | ✗           | ✓     |
  | Assign artist→user  | ✗     | ✗           | ✓     |

- **rate limit matrix**:
  | User Type              | Rate Limit    |
  |------------------------|---------------|
  | Anonymous              | 100/minute    |
  | Logged-in Guest        | 200/minute    |
  | Artist-linked Guest    | 200/minute    |
  | Admin                  | 1000/minute   |
  | Upload (all users)     | 20/minute     |

- **audit logging**: RBAC denials logged with reason ('insufficient_role' vs 'not_owner')
- **backwards compatibility**: existing 'visitor' users automatically treated as 'guest'
- **migration path**: Alembic migration updates database, code fallback for safety

see `backend/tests/test_rbac_rate_limits.py` for comprehensive test coverage.

---

## High Priority (Core Security)

### Authentication & Authorization
- [x] **User Authentication System** - COMPLETED
  - [x] Implement user registration with email validation
  - [x] Add password hashing with bcrypt (min 12 rounds)
  - [x] Create login endpoint with rate limiting placeholder (TODO: add Flask-Limiter)
  - [x] Implement secure session management
  - [x] Add "remember me" functionality with secure tokens

- [x] **Role-Based Access Control (RBAC)** - COMPLETED
  - [x] Define user roles: Admin, Guest (normalized from Visitor)
  - [x] Create decorators for role checking (@admin_required, @login_required)
  - [x] Implement permission system for artwork management (owner-based RBAC)
  - [x] Dynamic rate limiting by user identity (anonymous/guest/admin)
  - [ ] Admin dashboard access control (pending frontend implementation)

### Input Validation & Sanitization
- [x] **API Input Validation** - COMPLETED for Auth
  - [x] Validate all user inputs (username, email, passwords)
  - [x] Sanitize inputs to prevent SQL injection (using SQLAlchemy ORM)
  - [x] Implement length limits and character restrictions (email max 254, password max 128)
  - [x] Add email format validation
  
- [x] **File Upload Security** - COMPLETED
  - [x] Whitelist allowed file types (JPG, PNG, WebP, AVIF)
  - [x] Validate file size limits (max 10MB)
  - [x] Check file headers via magic bytes, not just extensions
  - [x] Sanitize filenames to prevent path traversal
  - [x] Store files outside web root (in dedicated uploads directory)
  - [x] Format-safe processing (respect MIME type in save options, prevent JPEG params on PNG/WebP/AVIF)
  - [x] Ownership enforcement (artist-user linking via `artist.user_id` foreign key)
  - [x] Admin endpoints for artist-user management (`assign-user`, `unassign-user`)
  - [x] Orphaned upload controls (admin-only policy prevents storage abuse)
  - [ ] Implement virus scanning (optional: ClamAV integration) - Deferred for future enhancement

### Session & Cookie Security
- [x] **Secure Session Configuration** - COMPLETED
  - [x] Set HttpOnly flag on cookies
  - [x] Set Secure flag for HTTPS (configurable via SESSION_COOKIE_SECURE env var)
  - [x] Configure SameSite attribute (Lax)
  - [x] Implement session timeout (30 min inactivity)
  - [x] Add session regeneration on login

### CSRF Protection
- [x] **Cross-Site Request Forgery** - COMPLETED (fix-privilege-escalation-csrf branch)
  - [x] Implement CSRF tokens for all POST/PUT/DELETE requests
  - [x] Configure Flask-WTF CSRF protection
  - [x] Add CSRF token to frontend forms (via /auth/csrf-token endpoint)
  - [x] Configure CSRF exemptions only for truly stateless API endpoints

### CORS Configuration
- [x] **Cross-Origin Resource Sharing** - COMPLETED (fix-cookie-cors-input-validation branch)
  - [x] Move origins from hardcoded `http://localhost:5173` to environment variable (CORS_ORIGINS)
  - [x] Support multiple origins (dev, staging, prod) via comma-separated values
  - [x] Set appropriate CORS headers
  - [x] Restrict to specific HTTP methods
  - [x] Configure credentials policy (currently supports_credentials=True for /api/* and /auth/*)

## Medium Priority (Additional Security)

### Rate Limiting
- [x] **Brute Force Protection** - COMPLETED (fix-privilege-escalation-csrf branch)
  - [x] Add Flask-Limiter dependency to requirements.txt
  - [x] Add rate limiting to login endpoint (5 attempts per 15 min per IP)
  - [x] Implement account lockout after 5 failed attempts (15 min lockout)
  - [x] Add IP-based blocking for repeated violations
  - [x] Log failed login attempts for security monitoring
  - [x] Rate limit registration endpoint (3 per minute cap, skipped in tests)
  - [x] Rate limit file uploads (pending file upload feature)

### Database Security
- [x] **SQL Injection Prevention**
  - [x] Use SQLAlchemy ORM for all queries
  - [x] Never use raw SQL with user input
  - [x] Parameterize any necessary raw queries
  
- [x] **Connection Security**
  - [x] Use environment variables for DB credentials (DB_HOST/PORT/NAME/USER/PASSWORD + fallback DATABASE_URL)
  - [x] Implement connection pooling (SQLALCHEMY_ENGINE_OPTIONS via DB_POOL_* env vars)
  - [x] Enable SSL for DB connections in production (DB_SSL_MODE + optional DB_SSL_ROOT_CERT)

### XSS Protection
- [x] **Cross-Site Scripting Prevention** - COMPLETED (implement-xss-protection branch)
  - [x] Escape all user-generated content - HTML escaping utility added (defense-in-depth)
  - [x] Set Content-Security-Policy headers - Strict CSP policy implemented for JSON API
  - [x] Sanitize HTML in artwork descriptions - HTML sanitization utility added (ready for future use)
  - [x] Use secure templating practices - Frontend uses Svelte's automatic escaping, JSON responses use jsonify()

### API Security
- [ ] **JWT Token Implementation**
  - [ ] Generate JWT tokens on login
  - [ ] Add token expiration (1 hour)
  - [ ] Implement refresh token mechanism
  - [ ] Validate tokens on protected endpoints

### Logging & Monitoring
- [x] **Security Audit Logging** - COMPLETED (fix-privilege-escalation-csrf branch)
  - [x] Implement structured audit logging (JSON format in details field)
  - [x] Log all authentication attempts (success and failure)
  - [x] Log failed login attempts with IP address and user agent
  - [x] Log account lockout events
  - [x] Log rate limit exceeded events
  - [ ] Log admin actions and role changes (pending admin promotion endpoint)
  - [x] Log sensitive operations (password resets, account modifications)
  - [ ] Log file uploads (pending file upload feature)
  - [ ] Set up log rotation and aggregation (operational concern)
  - [ ] Configure alerting for suspicious patterns (operational concern)

## Low Priority (Enhanced Security)

### HTTPS/TLS
- [ ] Configure HTTPS in production
- [ ] Force HTTPS redirects
- [ ] Implement HSTS headers

### Password Policies
- [x] Minimum length: 8 characters
- [x] Require uppercase, lowercase, number, special char
- [x] Prevent common passwords
- [x] Implement password strength meter

### Two-Factor Authentication (Optional)
- [ ] Add TOTP-based 2FA
- [ ] Backup codes generation
- [ ] 2FA recovery process

### Security Headers
- [x] X-Frame-Options: DENY
- [x] X-Content-Type-Options: nosniff
- [x] Referrer-Policy: no-referrer
- [x] Permissions-Policy
- [x] Content-Security-Policy - Strict policy for JSON API (default-src 'self', script-src 'self', object-src 'none', frame-ancestors 'none')

### Penetration Testing
- [x] SQL injection testing
- [x] XSS vulnerability testing
- [x] CSRF testing
- [ ] File upload bypass testing
- [ ] Authentication bypass testing

### Password Changes 
- [ ] Require current passwords before allowing a change 
- [ ] validate current password using same rules for reg (length, complexity etc)
- [ ] log password changes in audit log 
- [ ] require re-auth for sensistive ops after password change 


### Prevent Account duplicates (Check)
 - [ ] Just check to see if a user can register a account using a email already registered
Notes:
  make sure to use bycrpt to generate the hash, update hashed passoword in password field under user model, and consider invalidating all existing sessions after change (revoke csrf tokens)


## Implementation Priority Order

### phase 1 (completed - feat/auth-session-hardening branch)
1. ~~user authentication (login/register/logout)~~ completed
2. ~~password hashing with bcrypt~~ completed
3. ~~input validation and sanitization~~ completed (needs improvements)
4. ~~RBAC implementation~~ completed (role assignment broken)
5. ~~session security configuration~~ completed (defaults need fixing)

### phase 2 (CRITICAL - must fix before production)
1. ~~**fix privilege escalation**~~ - COMPLETED: remove client-controlled role assignment
2. ~~**implement CSRF protection**~~ - COMPLETED: add Flask-WTF CSRF tokens
3. ~~**fix insecure cookie defaults**~~ - COMPLETED: flip secure flags to true by default
4. ~~**fix information disclosure**~~ - COMPLETED: remove str(e) from error responses
5. ~~**add rate limiting**~~ - COMPLETED: prevent brute force attacks
6. ~~**implement audit logging**~~ - COMPLETED: detect security breaches
7. ~~**fix CORS configuration**~~ - COMPLETED: move to environment variables
8. ~~**add account lockout**~~ - COMPLETED: protect against credential stuffing
9. ~~**add input length validation**~~ - COMPLETED: prevent DoS via long inputs (email max 254, password max 128)

### phase 3 (COMPLETED - upload security hardening)
1. ~~**format-safe image processing**~~ - COMPLETED: respect MIME type in save options
2. ~~**ownership enforcement**~~ - COMPLETED: artist-user linking with `user_id` foreign key
3. ~~**admin artist management**~~ - COMPLETED: assign/unassign endpoints
4. ~~**orphaned upload controls**~~ - COMPLETED: admin-only policy
5. ~~**upload security tests**~~ - COMPLETED: comprehensive test suite

### phase 4 (COMPLETED - RBAC & Dynamic Rate Limiting - November 2025)
1. ~~**role normalization (visitor→guest)**~~ - COMPLETED: semantic improvement with backwards compatibility
2. ~~**dynamic rate limiting by identity**~~ - COMPLETED: different limits for anonymous/guest/admin
3. ~~**RBAC decorators and helpers**~~ - COMPLETED: owner checking, audit logging
4. ~~**ownership-based RBAC enforcement**~~ - COMPLETED: owners can edit/delete artworks and photos
5. ~~**comprehensive RBAC tests**~~ - COMPLETED: test suite for all permission scenarios

### phase 5 (future enhancements)
10. JWT token implementation
11. two-factor authentication
12. penetration testing
13. HTTPS/TLS in production
14. orphaned photo cleanup job (delete unassociated photos after X days)

## sources

- Flask-Login: https://flask-login.readthedocs.io/
- Flask-Bcrypt: https://flask-bcrypt.readthedocs.io/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Flask Security Best Practices: https://flask.palletsprojects.com/en/2.3.x/security/
