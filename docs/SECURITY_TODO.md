# Security Implementation TODO List For JC

## current sprint plan (phase 2 - security hardening)

### immediate priorities
1. **fix critical security issues** (privilege escalation, cookie defaults, information disclosure)
2. **add csrf protection** (Flask-WTF already installed, needs configuration)
3. **enable rate limiting** (Flask-Limiter ready to uncomment)
4. **build authentication UI** (login/register forms in SvelteKit)

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
- [ ] **privilege escalation via self-service admin role** (`backend/auth.py:96-142`)
  - registration endpoint trusts client-supplied role parameter
  - anyone can pass `"role": "admin"` during signup to gain full admin access
  - **fix**: remove role from registration input, force all new users to 'visitor', create admin promotion endpoint requiring existing admin auth

- [ ] **csrf protection missing** (`backend/app.py:86-88`, `backend/auth.py:72-210`)
  - Flask-WTF installed but not configured
  - session-based auth endpoints vulnerable to cross-site request forgery
  - **fix**: enable Flask-WTF CSRF protection, add tokens to all POST/PUT/DELETE requests, configure exemptions only for truly stateless endpoints

- [ ] **insecure cookie defaults** (`backend/app.py:25-33`)
  - SESSION_COOKIE_SECURE and REMEMBER_COOKIE_SECURE default to False
  - cookies will ride over plain HTTP unless env var manually set in prod
  - **fix**: flip defaults to secure=true, require explicit opt-out for local dev only, add startup validation

- [ ] **information disclosure in error responses** (`backend/auth.py:132-148`)
  - registration failures echo `str(e)` to client, leaking database/stack details
  - **fix**: replace with generic error messages, log detailed errors server-side only

### major issues
- [ ] **rate limiting not implemented** - unlimited login attempts possible, brute force attacks viable
- [ ] **hardcoded cors origins** - `http://localhost:5173` won't work in production
- [ ] **no account lockout mechanism** - no protection against repeated failed login attempts
- [ ] **no audit logging** - cannot detect or investigate security breaches

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

## High Priority (Core Security)

### Authentication & Authorization
- [x] **User Authentication System** - COMPLETED
  - [x] Implement user registration with email validation
  - [x] Add password hashing with bcrypt (min 12 rounds)
  - [x] Create login endpoint with rate limiting placeholder (TODO: add Flask-Limiter)
  - [x] Implement secure session management
  - [x] Add "remember me" functionality with secure tokens

- [x] **Role-Based Access Control (RBAC)** - COMPLETED
  - [x] Define user roles: Admin, Visitor
  - [x] Create decorators for role checking (@admin_required, @login_required)
  - [ ] Implement permission system for artwork management (pending artwork features)
  - [ ] Admin dashboard access control (pending frontend implementation)

### Input Validation & Sanitization
- [x] **API Input Validation** - COMPLETED for Auth
  - [x] Validate all user inputs (username, email, passwords)
  - [x] Sanitize inputs to prevent SQL injection (using SQLAlchemy ORM)
  - [x] Implement length limits and character restrictions
  - [x] Add email format validation
  
- [ ] **File Upload Security**
  - [ ] Whitelist allowed file types (jpg, png, gif)
  - [ ] Validate file size limits (max 10MB)
  - [ ] Check file headers, not just extensions
  - [ ] Sanitize filenames to prevent path traversal
  - [ ] Store files outside web root
  - [ ] Implement virus scanning (optional: ClamAV integration)

### Session & Cookie Security
- [x] **Secure Session Configuration** - COMPLETED
  - [x] Set HttpOnly flag on cookies
  - [x] Set Secure flag for HTTPS (configurable via SESSION_COOKIE_SECURE env var)
  - [x] Configure SameSite attribute (Lax)
  - [x] Implement session timeout (30 min inactivity)
  - [x] Add session regeneration on login

### CSRF Protection
- [ ] **Cross-Site Request Forgery** - CRITICAL (see audit section above)
  - [ ] Implement CSRF tokens for all POST/PUT/DELETE requests
  - [ ] Configure Flask-WTF CSRF protection
  - [ ] Add CSRF token to frontend forms
  - [ ] Configure CSRF exemptions only for truly stateless API endpoints

### CORS Configuration
- [ ] **Cross-Origin Resource Sharing** - MAJOR (hardcoded origins won't work in production)
  - [ ] Move origins from hardcoded `http://localhost:5173` to environment variable
  - [ ] Support multiple origins (dev, staging, prod)
  - [ ] Set appropriate CORS headers
  - [ ] Restrict to specific HTTP methods
  - [ ] Configure credentials policy (currently supports_credentials=True for /api/* and /auth/*)

## Medium Priority (Additional Security)

### Rate Limiting
- [ ] **Brute Force Protection** - MAJOR (unlimited login attempts currently possible)
  - [ ] Add Flask-Limiter dependency to requirements.txt
  - [ ] Add rate limiting to login endpoint (5 attempts per 15 min per IP)
  - [ ] Implement account lockout after 5 failed attempts (15 min lockout)
  - [ ] Rate limit registration endpoint
  - [ ] Rate limit file uploads
  - [ ] Add IP-based blocking for repeated violations
  - [ ] Log failed login attempts for security monitoring

### Database Security
- [ ] **SQL Injection Prevention**
  - [ ] Use SQLAlchemy ORM for all queries
  - [ ] Never use raw SQL with user input
  - [ ] Parameterize any necessary raw queries
  
- [ ] **Connection Security**
  - [ ] Use environment variables for DB credentials
  - [ ] Implement connection pooling
  - [ ] Enable SSL for DB connections in production

### XSS Protection
- [ ] **Cross-Site Scripting Prevention**
  - [ ] Escape all user-generated content
  - [ ] Set Content-Security-Policy headers
  - [ ] Sanitize HTML in artwork descriptions
  - [ ] Use secure templating practices

### API Security
- [ ] **JWT Token Implementation**
  - [ ] Generate JWT tokens on login
  - [ ] Add token expiration (1 hour)
  - [ ] Implement refresh token mechanism
  - [ ] Validate tokens on protected endpoints

### Logging & Monitoring
- [ ] **Security Audit Logging** - MAJOR (cannot detect or investigate security breaches currently)
  - [ ] Implement structured audit logging (JSON format recommended)
  - [ ] Log all authentication attempts (success and failure)
  - [ ] Log failed login attempts with IP address and user agent
  - [ ] Log admin actions and role changes
  - [ ] Log sensitive operations (password resets, account modifications)
  - [ ] Log file uploads
  - [ ] Set up log rotation and aggregation
  - [ ] Configure alerting for suspicious patterns

## Low Priority (Enhanced Security)

### HTTPS/TLS
- [ ] Configure HTTPS in production
- [ ] Force HTTPS redirects
- [ ] Implement HSTS headers

### Password Policies
- [ ] Minimum length: 8 characters
- [ ] Require uppercase, lowercase, number, special char
- [ ] Prevent common passwords
- [ ] Implement password strength meter

### Two-Factor Authentication (Optional)
- [ ] Add TOTP-based 2FA
- [ ] Backup codes generation
- [ ] 2FA recovery process

### Security Headers
- [x] X-Frame-Options: DENY
- [x] X-Content-Type-Options: nosniff
- [x] Referrer-Policy: no-referrer
- [x] Permissions-Policy

### Penetration Testing
- [ ] SQL injection testing
- [ ] XSS vulnerability testing
- [ ] CSRF testing
- [ ] File upload bypass testing
- [ ] Authentication bypass testing

## Implementation Priority Order

### phase 1 (completed - feat/auth-session-hardening branch)
1. ~~user authentication (login/register/logout)~~ completed
2. ~~password hashing with bcrypt~~ completed
3. ~~input validation and sanitization~~ completed (needs improvements)
4. ~~RBAC implementation~~ completed (role assignment broken)
5. ~~session security configuration~~ completed (defaults need fixing)

### phase 2 (CRITICAL - must fix before production)
1. **fix privilege escalation** - remove client-controlled role assignment
2. **implement CSRF protection** - add Flask-WTF CSRF tokens
3. **fix insecure cookie defaults** - flip secure flags to true by default
4. **fix information disclosure** - remove str(e) from error responses
5. **add rate limiting** - prevent brute force attacks
6. **implement audit logging** - detect security breaches
7. **fix CORS configuration** - move to environment variables
8. **add account lockout** - protect against credential stuffing
9. **add input length validation** - prevent DoS via long inputs

### phase 3 (future enhancements)
10. file upload security
11. JWT token implementation
12. two-factor authentication
13. penetration testing
14. HTTPS/TLS in production

## sources

- Flask-Login: https://flask-login.readthedocs.io/
- Flask-Bcrypt: https://flask-bcrypt.readthedocs.io/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Flask Security Best Practices: https://flask.palletsprojects.com/en/2.3.x/security/

