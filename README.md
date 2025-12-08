# Canvas & Clay

A local-first digital gallery and artwork management system. Admins manage artworks securely while visitors browse public galleries over the local network.

## Features

- **Gallery Browsing** - Public artwork viewing with search and filtering
- **Artist Portfolios** - Manage artist profiles and their artwork collections
- **Photo Uploads** - Support for JPEG, PNG, WebP, and AVIF formats with automatic thumbnail generation
- **Admin Console** - User management, artwork administration, and platform settings
- **Dark/Light Mode** - Theme toggle for comfortable viewing
- **Help Center** - FAQ, guides, and contact form
- **Admin-Editable Legal Pages** - Privacy Policy and Terms of Service management

## Getting Started

### Step 1: Prerequisites

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Step 2: Clone the Repository

```bash
git clone https://github.com/cjaron03/canvas-and-clay.git
cd canvas-and-clay
```

### Step 3: Configure Environment

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

### Step 4: Start the Application

```bash
docker compose -f infra/docker-compose.yml up --build
```

Wait for the containers to start (first build takes 2-3 minutes).

### Step 5: Seed Demo Data (Optional)

In a new terminal, populate the database with sample artists and artworks:

```bash
docker compose -f infra/docker-compose.yml exec backend python seed_artworks.py
```

### Step 6: Access the Application

Open http://localhost:5173 in your browser

### Step 7: Sign In as Admin

- Click "Sign in" in the top right
- Email: `admin@canvas-clay.local`
- Password: `ChangeMe123`

You now have full admin access to manage users, artworks, and settings.

## User Roles

| Role | Capabilities |
|------|--------------|
| **Guest** | Browse public gallery, view artist portfolios |
| **Artist** | Upload and manage own artworks, edit profile |
| **Admin** | Full platform management, user administration |

## Scripts & Tools

### Seed Demo Data

Populate the database with sample content:

```bash
# Seed artists, artworks, and storage locations
docker compose -f infra/docker-compose.yml exec backend python seed_artworks.py

# Seed user accounts (configure via environment variables)
docker compose -f infra/docker-compose.yml exec backend python seed_users.py
```

### Upload Wizard

Interactive bulk upload tool:

```bash
# From project root
./upload.sh path/to/artwork.zip

# Preview steps without uploading
./upload.sh --preview
```

The wizard guides you through:
1. Admin login
2. Artist selection/creation
3. Storage location
4. Artwork distribution
5. Auto-manifest generation

### Database Backup

```bash
docker compose -f infra/docker-compose.yml exec backend bash /app/tools/backup.sh
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | SvelteKit |
| Backend | Flask REST API |
| Database | PostgreSQL |
| Infrastructure | Docker Compose |

## Ports

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:5001 |
| Database | localhost:5432 |

## Troubleshooting

**"Cannot connect to the Docker daemon"**
- Make sure Docker Desktop is running

**"Port already in use"**
- Stop any services using ports 5173, 5001, or 5432
- Or modify the port mappings in `infra/docker-compose.yml`

**"docker-compose: command not found"**
- Use `docker compose` (with space, not hyphen) for Docker Compose v2
- Or install Docker Compose v1: `pip install docker-compose`

**Database connection errors**
- Ensure `backend/.env` has `DB_HOST=db` (not `localhost`)
- Verify credentials match: `DB_USER=canvas_db`, `DB_PASSWORD=clay123`

**Admin login not working**
- Wait 30 seconds after first startup for the bootstrap admin to be created
- Check credentials: `admin@canvas-clay.local` / `ChangeMe123`

## Documentation

- `CLAUDE.md` - Development guide and codebase overview
- `docs/` - Additional technical documentation
