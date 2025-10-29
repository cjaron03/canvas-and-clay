# Testing Security Fixes Guide

This guide shows how to test the three critical security fixes:
1. Insecure cookie defaults (now secure by default)
2. CORS configuration (environment variable)
3. Input length validation (DoS prevention)

## Quick Test - Automated Tests

Run all tests to verify everything works:

```bash
cd infra
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

This runs all 40 tests including the new input length validation tests.

## Manual Testing

### 1. Start the Application

```bash
cd infra
docker compose up --build
```

The app will be available at:
- Frontend: http://localhost:5173
- Backend API: http://localhost:5001

### 2. Test Cookie Defaults (Secure Flag)

**Check startup warnings:**

When the backend starts, you should see warnings if insecure configuration is detected:

```bash
# Check backend logs
docker logs canvas_backend
```

You should see warnings like:
```
warning: CORS origins include localhost: ['http://localhost:5173']
warning: ensure CORS_ORIGINS is configured correctly for production
```

**Test secure cookies in production mode:**

1. Stop the containers: `docker compose down`
2. Set environment variable for local dev (allows insecure cookies):
   ```bash
   cd backend
   echo "ALLOW_INSECURE_COOKIES=true" >> .env
   ```
3. Restart: `cd ../infra && docker compose up`
4. Check logs - you should see:
   ```
   warning: ALLOW_INSECURE_COOKIES is enabled - cookies will be sent over HTTP
   warning: this should only be used in local development, not in production
   ```

**Verify cookie security:**

Open browser dev tools (F12) → Network tab → make a request → check cookies:

- Without `ALLOW_INSECURE_COOKIES=true`: Cookies should have `Secure` flag (requires HTTPS)
- With `ALLOW_INSECURE_COOKIES=true`: Cookies won't have `Secure` flag (works on HTTP)

### 3. Test CORS Configuration

**Test default (localhost):**

The default CORS origin is `http://localhost:5173`. This should work automatically.

**Test custom CORS origins:**

1. Stop containers: `docker compose down`
2. Set custom CORS origins in `backend/.env`:
   ```bash
   CORS_ORIGINS=http://localhost:5173,https://example.com,https://staging.example.com
   ```
3. Restart: `docker compose up`
4. Test from different origins using curl or browser console

**Test CORS from browser console:**

Open http://localhost:5173 and run in browser console:

```javascript
// This should work (same origin)
fetch('http://localhost:5001/api/hello', {
  credentials: 'include'
}).then(r => r.json()).then(console.log);
```

### 4. Test Input Length Validation

**Test email max length (254 characters):**

```bash
# Using curl
curl -X POST http://localhost:5001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'$(python3 -c "print('a' * 245 + '@example.com')")'",
    "password": "SecurePass123"
  }'
```

Expected response: `400 Bad Request` with error "Email must be no more than 254 characters"

**Test password max length (128 characters):**

```bash
# Using curl
curl -X POST http://localhost:5001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "'$(python3 -c "print('A' + 'a' * 127 + '1')")'"
  }'
```

Expected response: `400 Bad Request` with error "Password must be no more than 128 characters"

**Test from browser console:**

Visit http://localhost:5173 and run:

```javascript
// Test email too long (255 chars) - wrap in async IIFE for console
(async () => {
  const longEmail = 'a'.repeat(245) + '@example.com';
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const result = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({
      email: longEmail,
      password: 'SecurePass123'
    })
  }).then(r => r.json());

  console.log('Result:', result);
  // Should show error about 254 character limit
})();
```

```javascript
// Test password too long (129 chars) - wrap in async IIFE for console
(async () => {
  const longPassword = 'A' + 'a'.repeat(127) + '1';
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const result = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({
      email: 'test@example.com',
      password: longPassword
    })
  }).then(r => r.json());

  console.log('Result:', result);
  // Should show error about 128 character limit
})();
```

**Test valid inputs (should work):**

```javascript
// Valid email (254 chars exactly - should work)
(async () => {
  const validLongEmail = 'a'.repeat(244) + '@ex.co'; // 254 chars total
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const result = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({
      email: validLongEmail,
      password: 'SecurePass123'
    })
  }).then(r => r.json());

  console.log('Result:', result);
  // Should succeed (201 Created)
})();
```

```javascript
// Valid password (128 chars exactly - should work)
(async () => {
  const validLongPassword = 'A' + 'a'.repeat(125) + '1'; // 128 chars total
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const result = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({
      email: 'another@example.com',
      password: validLongPassword
    })
  }).then(r => r.json());

  console.log('Result:', result);
  // Should succeed (201 Created)
})();
```

## Running Specific Tests

**Run only input length validation tests:**

```bash
cd infra
docker compose -f docker-compose.test.yml run --rm backend \
  python -m pytest tests/test_auth.py::TestUserRegistration::test_register_email_too_long \
    tests/test_auth.py::TestUserRegistration::test_register_password_too_long \
    tests/test_auth.py::TestUserLogin::test_login_email_too_long \
    tests/test_auth.py::TestUserLogin::test_login_password_too_long -v
```

**Run all authentication tests:**

```bash
cd infra
docker compose -f docker-compose.test.yml run --rm backend \
  python -m pytest tests/test_auth.py -v
```

**Run all tests:**

```bash
cd infra
docker compose -f docker-compose.test.yml run --rm backend \
  python -m pytest tests/ -v
```

## Verification Checklist

- [ ] All 40 tests pass
- [ ] Startup warnings appear for insecure config
- [ ] Cookies default to Secure=True (check in browser dev tools)
- [ ] `ALLOW_INSECURE_COOKIES=true` allows HTTP cookies
- [ ] CORS works with default localhost origin
- [ ] CORS works with custom origins from env var
- [ ] Email > 254 chars rejected
- [ ] Password > 128 chars rejected
- [ ] Email = 254 chars accepted
- [ ] Password = 128 chars accepted
- [ ] Validation works on both /auth/register and /auth/login

## Environment Variables Reference

Add these to `backend/.env` for testing:

```bash
# Allow insecure cookies for local dev (default: false)
ALLOW_INSECURE_COOKIES=true

# CORS origins (comma-separated, default: http://localhost:5173)
CORS_ORIGINS=http://localhost:5173,https://example.com
```

## Troubleshooting

**Tests fail with "database not ready":**
- Wait a few seconds for database to initialize
- Check: `docker logs canvas_db_test`

**CORS errors in browser:**
- Check `CORS_ORIGINS` env var matches your frontend URL
- Ensure `supports_credentials=True` is set (it is by default)

**Cookies not working:**
- For local dev, set `ALLOW_INSECURE_COOKIES=true` in `backend/.env`
- Check browser console for CORS/cookie errors
- Ensure `credentials: 'include'` in fetch requests

