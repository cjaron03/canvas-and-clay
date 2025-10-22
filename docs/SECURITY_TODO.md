# Security Implementation TODO List For JC

## Recent Updates

**Completed in feat/auth-session-hardening branch:**
- User authentication system with registration, login, and logout
- Bcrypt password hashing with strong password requirements
- Secure session management with HttpOnly, Secure, and SameSite cookies
- Role-based access control (RBAC) with @login_required and @admin_required decorators
- Remember-me functionality with secure token management
- Comprehensive test suite for authentication and session security
- API input validation for authentication endpoints

See the Authentication & Security section in README.md for full details.

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
- [ ] **Cross-Site Request Forgery**
  - [ ] Implement CSRF tokens for all POST/PUT/DELETE requests
  - [ ] Configure Flask-WTF CSRF protection
  - [ ] Add CSRF token to frontend forms

### CORS Configuration
- [ ] **Cross-Origin Resource Sharing**
  - [ ] Configure allowed origins (localhost:5173 for dev)
  - [ ] Set appropriate CORS headers
  - [ ] Restrict to specific HTTP methods
  - [ ] Configure credentials policy

## Medium Priority (Additional Security)

### Rate Limiting
- [ ] **Brute Force Protection**
  - [ ] Add rate limiting to login endpoint (5 attempts per 15 min)
  - [ ] Rate limit registration endpoint
  - [ ] Rate limit file uploads
  - [ ] Add IP-based blocking for repeated violations

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
- [ ] **Security Audit Logging**
  - [ ] Log all authentication attempts
  - [ ] Log failed login attempts with IP
  - [ ] Log admin actions
  - [ ] Log file uploads
  - [ ] Set up log rotation

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

1. User authentication (login/register/logout)
2. Password hashing with bcrypt
3. Input validation and sanitization
4. CSRF protection
5. Rate limiting on auth endpoints
6. File upload security
7. CORS configuration
8. RBAC implementation
9. Session security configuration
10. Security logging

## sources

- Flask-Login: https://flask-login.readthedocs.io/
- Flask-Bcrypt: https://flask-bcrypt.readthedocs.io/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Flask Security Best Practices: https://flask.palletsprojects.com/en/2.3.x/security/

