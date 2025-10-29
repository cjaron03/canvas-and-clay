# Canvas & Clay - Capstone Project 
> Local first digital gallery and artwork management per SRS
> Project allows administrators to securely manage artworks while visitors can browse public digital galleries over the local network 

## Architecture Overview 
- **Frontend** SvelteKit
- **Backend**  Flask (REST API)
- **Database** PostgreSQL (Dockerized)
- **Infra**    Docker Compose for local development and GitHub Actions for CI/CD

Simple Architecture diagram should be added to '/docs/arch.png'

## Running Locally

### Quick Start with Docker 
1. **Install Docker Desktop** from [docker.com](https://www.docker.com/products/docker-desktop/)
2. **Clone the repository**
   ```bash
   git clone https://github.com/cjaron03/canvas-and-clay.git
   cd canvas-and-clay
   ```
3. **Copy environment files** (adjust values if needed)
   ```bash
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   ```
4. **Run**
   ```bash
   cd infra
   docker compose up --build
   ```

**Ports**
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5001
- **Database**: localhost:5432

**Stop the application:**
```bash
docker compose down
```

---

## Development Setup (Without Docker)

### Prerequisites
- Node.js 20+
- Python 3.12+
- PostgreSQL 15+

### Backend (Flask)
```bash
cd backend
cp .env.example .env  # Copy environment file
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Frontend (SvelteKit)
```bash
cd frontend
cp .env.example .env  # Copy environment file
npm install
npm run dev
```

**Environment Configuration:**
- Backend `.env`: Configure database connection and Flask settings
- Frontend `.env`: Configure API base URL (default: `http://localhost:5001`)
  - `PUBLIC_API_BASE_URL`: Points to the backend API (must be prefixed with `PUBLIC_` for SvelteKit)

## Docker Optimization

This project uses **multi-stage builds** and **BuildKit** for optimized Docker performance:

### Features
- **Multi-stage builds**: Separate build and runtime stages for smaller images
- **BuildKit cache mounts**: Persistent pip/npm caches across builds
- **Alpine base**: Frontend uses `node:20-alpine` for minimal footprint
- **Slim base**: Backend uses `python:3.12-slim` for faster wheel installs
- **Layer caching**: Optimized Dockerfile instruction order

### Enabling BuildKit Locally

BuildKit provides significant performance improvements through parallel builds and advanced caching.

**Check if BuildKit is enabled:**
```bash
docker info | grep BuildKit
```

**Enable BuildKit (one-time setup):**
```bash
# Option 1: Set environment variable (per-command)
export DOCKER_BUILDKIT=1
docker build ...

# Option 2: Enable globally in Docker config
mkdir -p ~/.docker
echo '{ "features": { "buildkit": true } }' > ~/.docker/config.json

# Option 3: Docker Desktop users (Mac/Windows)
# BuildKit is enabled by default in recent versions
```

**Verify BuildKit is working:**
```bash
DOCKER_BUILDKIT=1 docker build backend/
# You should see output like: "[internal] load build definition from Dockerfile"
```

### Build Performance
- **First build**: ~2-3 minutes (downloads all dependencies)
- **Subsequent builds**: ~10-30 seconds (uses cache mounts)
- **CI/CD caching**: GitHub Actions cache reduces build time by ~60%

### Docker Build Context Optimization

Each service includes a `.dockerignore` file to exclude unnecessary files from the Docker build context, significantly reducing build time and image size.

**Backend `.dockerignore`** excludes:
- Python cache files (`__pycache__/`, `*.pyc`)
- Virtual environments (`venv/`, `.venv/`)
- Test files and coverage reports (`tests/`, `.pytest_cache/`, `.coverage`)
- Development tools (`.vscode/`, `.idea/`)
- Documentation (`docs/`, `*.md`)
- Environment files (`.env` - use `.env.example` instead)
- Git and CI/CD metadata (`.git/`, `.github/`)

**Frontend `.dockerignore`** excludes:
- Node modules (`node_modules/` - installed fresh in container)
- Build outputs (`.svelte-kit/`, `build/`, `dist/`)
- Test files (`**/*.test.ts`, `tests/`)
- Development tools (`.vscode/`, `.idea/`)
- Documentation (`docs/`, `*.md`)
- Environment files (`.env` - use `.env.example` instead)
- Git and CI/CD metadata (`.git/`, `.github/`)

**Why this matters:**
- Smaller build context = faster uploads to Docker daemon
- Cleaner images without unnecessary development files
- Prevents accidental inclusion of sensitive files (`.env`, credentials)
- Reduces security surface area in production images

## CI/CD Pipeline

This project includes a comprehensive CI/CD pipeline with:

- **Backend Testing**: Python tests with pytest and coverage
- **Frontend Testing**: SvelteKit tests with Vitest
- **Code Quality**: ESLint for frontend, flake8 for backend
- **Docker Builds**: Automated container builds with Alpine Linux
- **Security Scanning**: Trivy vulnerability scanning
- **Deployment**: Automated staging and production deployments

### Pipeline Triggers
- **Push to `main`**: Full pipeline + production deployment
- **Push to `develop`**: Full pipeline + staging deployment  
- **Pull Requests**: Full pipeline validation

## Authentication & Security

This project implements comprehensive authentication and session security.

### Features Implemented

**User Authentication:**
- User registration with email validation
- Secure password hashing with bcrypt (12 rounds)
- Login/logout with session management
- Remember-me functionality (14-day token expiration)
- Account status management (active/disabled)

**Password Security:**
- Minimum 8 characters
- Must contain uppercase, lowercase, and digits
- Bcrypt hashing with salt

**Session Security:**
- HTTP-only cookies (prevents XSS access)
- SameSite=Lax (CSRF protection)
- Secure flag for HTTPS (configurable via `SESSION_COOKIE_SECURE` env var)
- 30-minute session timeout
- Session regeneration on login (prevents fixation attacks)
- Strong session protection enabled

**Role-Based Access Control (RBAC):**
- Two roles: `admin` and `visitor`
- `@login_required` decorator for protected routes
- `@admin_required` decorator for admin-only routes
- Role-based access control for sensitive operations

**API Endpoints:**
- `GET /auth/csrf-token` - Get CSRF token for frontend requests
- `POST /auth/register` - Create new user account (requires CSRF token)
- `POST /auth/login` - Authenticate and create session (requires CSRF token)
- `POST /auth/logout` - End session and clear cookies (requires CSRF token)
- `GET /auth/me` - Get current user info
- `GET /auth/protected` - Example protected route
- `GET /auth/admin-only` - Example admin-only route

**CSRF Protection:**
All POST/PUT/DELETE endpoints require a CSRF token. Frontend must:
1. Fetch token from `GET /auth/csrf-token`
2. Include token in subsequent requests via `X-CSRFToken` header

Example:
```javascript
// fetch csrf token
const csrfResponse = await fetch('http://localhost:5001/auth/csrf-token', {
  credentials: 'include'
});
const { csrf_token } = await csrfResponse.json();

// use token in request
await fetch('http://localhost:5001/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': csrf_token
  },
  credentials: 'include',
  body: JSON.stringify({email: 'user@example.com', password: 'SecurePass123'})
});
```

### Environment Configuration

Create `backend/.env` from `backend/.env.example`:

```bash
# Session Security Settings
SESSION_COOKIE_SECURE=True  # Set to True in production with HTTPS

# Bootstrap Admin Configuration
BOOTSTRAP_ADMIN_EMAIL=admin@canvas-clay.local
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123  # change immediately after first login
```

**Important Notes:**
- For local development without HTTPS, set `SESSION_COOKIE_SECURE=False`
- The bootstrap admin user is automatically created/promoted on application startup
- All new user registrations are forced to 'visitor' role (security fix)
- Admin role can only be granted by existing admins (future admin promotion endpoint)

### Database Migrations

Initialize the database and apply migrations:

```bash
# In backend directory or Docker container
flask db init        # First time only
flask db migrate -m "Add user model"
flask db upgrade
```

### Testing Authentication

**Run the comprehensive test suite:**

```bash
cd backend
pytest tests/test_auth.py -v
```

Tests cover:
- User registration validation
- Login/logout flows
- Password security requirements
- Session security (httponly, samesite)
- RBAC (role-based access control)
- Account status management
- CSRF protection for state-changing endpoints

**Manual testing from browser console** (visit http://localhost:5173 first):

**Note:** CSRF protection is disabled by default in test mode. For production testing, enable it in `.env`:
```bash
WTF_CSRF_ENABLED=True
```

```javascript
(async () => {
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const registerResult = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({email: 'test@example.com', password: 'SecurePass123'})
  }).then(r => r.json());
  console.log('Register:', registerResult);

  const loginCsrf = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  }).then(r => r.json());

  const loginResult = await fetch('http://localhost:5001/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': loginCsrf.csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({email: 'test@example.com', password: 'SecurePass123'})
  }).then(r => r.json());
  console.log('Login:', loginResult);

  const protectedResult = await fetch('http://localhost:5001/auth/protected', {
    credentials: 'include'
  }).then(r => r.json());
  console.log('Protected route:', protectedResult);

  const logoutCsrf = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  }).then(r => r.json());

  const logoutResult = await fetch('http://localhost:5001/auth/logout', {
    method: 'POST',
    headers: {
      'X-CSRFToken': logoutCsrf.csrf_token
    },
    credentials: 'include'
  }).then(r => r.json());
  console.log('Logout:', logoutResult);
})();
```

**note:** on subsequent test runs, the register step will fail with "email already registered" error. this is expected. the test will still work because it logs in with the existing user. to test fresh registration, use a unique email (e.g., `test2@example.com`, `test3@example.com`)

### Testing Security Fixes

**Test 1: Privilege Escalation Prevention**
```javascript
(async () => {
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
    body: JSON.stringify({email: 'attacker@example.com', password: 'SecurePass123', role: 'admin'})
  }).then(r => r.json());
  
  console.log(result);
})();
```

**Test 2: Bootstrap Admin Login**
```javascript
(async () => {
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const loginResult = await fetch('http://localhost:5001/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({email: 'admin@canvas-clay.local', password: 'ChangeMe123'})
  }).then(r => r.json());
  
  console.log('Login:', loginResult);

  const adminResult = await fetch('http://localhost:5001/auth/admin-only', {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log('Admin route:', adminResult);
})();
```

**Test 3: CSRF Protection Enforcement**
```javascript
(async () => {
  const result = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify({email: 'nocsrf@example.com', password: 'SecurePass123'})
  }).then(r => r.json());
  
  console.log(result);
})();
```

**Test 4: Admin-Only Route Access Control**
```javascript
(async () => {
  const csrfResp = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  });
  const { csrf_token } = await csrfResp.json();

  const registerResult = await fetch('http://localhost:5001/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({email: 'visitor@example.com', password: 'SecurePass123'})
  }).then(r => r.json());
  
  console.log('Register:', registerResult);

  const loginCsrf = await fetch('http://localhost:5001/auth/csrf-token', {
    credentials: 'include'
  }).then(r => r.json());

  const loginResult = await fetch('http://localhost:5001/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': loginCsrf.csrf_token
    },
    credentials: 'include',
    body: JSON.stringify({email: 'visitor@example.com', password: 'SecurePass123'})
  }).then(r => r.json());
  
  console.log('Login:', loginResult);

  const adminResult = await fetch('http://localhost:5001/auth/admin-only', {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log('Admin route (should fail):', adminResult);
})();
```

## Project Structure
```
├── backend/           # Flask API
│   ├── app.py         # Main application
│   ├── requirements.txt
│   ├── Dockerfile
│   └── tests/         # Test files
├── frontend/          # SvelteKit app
│   ├── src/           # Source code
│   ├── package.json
│   └── Dockerfile
├── infra/             # Infrastructure
│   ├── docker-compose.yml
│   └── docker-compose.test.yml
└── .github/workflows/ # CI/CD configuration
```
