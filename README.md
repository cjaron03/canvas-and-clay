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
- **Setup Wizard** - Interactive TUI for easy installation and troubleshooting

## Getting Started

### Prerequisites

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Step 1: Clone the Repository

```bash
git clone https://github.com/cjaron03/canvas-and-clay.git
cd canvas-and-clay
```

### Step 2: Run the Setup Wizard

```bash
./setup.sh
```

You'll see the main menu:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                        Local-First Digital Gallery                           │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│          A secure artwork management system for artists and collectors.      │
│                                                                              │
│          ┌──────────────────────────────────────────────────────┐           │
│          │                                                      │           │
│          │  [1]  Setup      Configure environment and start     │           │
│          │                  services                            │           │
│          │  [2]  Repair     Scan for and fix common issues      │           │
│          │                                                      │           │
│          │  [q]  Quit                                           │           │
│          │                                                      │           │
│          └──────────────────────────────────────────────────────┘           │
│                                                                              │
│                           Press 1, 2, or q                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

Press `1` to start the setup process.

### Step 3: Prerequisites Check

The wizard checks your system:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                                 Setup                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 1 of 5: Checking Prerequisites                                        │
│   ──────────────────────────────────────────────────────────────────────     │
│                                                                              │
│       [OK]  Docker installed                                                 │
│       [OK]  Docker daemon running                                            │
│       [OK]  docker-compose available                                         │
│                                                                              │
│                        Press any key to continue...                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Step 4: Environment Configuration

The wizard creates your `.env` file with secure keys:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                                 Setup                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 2 of 5: Environment Configuration                                     │
│   ──────────────────────────────────────────────────────────────────────     │
│                                                                              │
│       [OK]  Created .env from template                                       │
│       [OK]  Generated SECRET_KEY                                             │
│       [OK]  Generated PII_ENCRYPTION_KEY                                     │
│                                                                              │
│   Admin Credentials:                                                         │
│       Email:    admin@canvas-clay.local                                      │
│       Password: ********                                                     │
│                                                                              │
│                        Press any key to continue...                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Step 5: Building Containers

Docker builds and starts the services:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                                 Setup                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 3 of 5: Building Containers                                           │
│   ──────────────────────────────────────────────────────────────────────     │
│                                                                              │
│   Building and starting Docker containers...                                 │
│   This may take a few minutes on first run.                                  │
│                                                                              │
│    ✔ Network infra_default        Created                                    │
│    ✔ Container canvas_db          Started                                    │
│    ✔ Container canvas_backend     Started                                    │
│    ✔ Container canvas_frontend    Started                                    │
│                                                                              │
│       [OK]  Containers started                                               │
│                                                                              │
│                        Press any key to continue...                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Step 6: Health Check

The wizard verifies services are running:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                                 Setup                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 4 of 5: Health Check                                                  │
│   ──────────────────────────────────────────────────────────────────────     │
│                                                                              │
│   Waiting for services to be ready...                                        │
│                                                                              │
│       [OK]  Backend is healthy                                               │
│       [OK]  Services are ready                                               │
│                                                                              │
│                        Press any key to continue...                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Step 7: Setup Complete

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                            Setup Complete                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Setup completed successfully!                                              │
│   ──────────────────────────────────────────────────────────────────────     │
│                                                                              │
│   Canvas & Clay is now running.                                              │
│                                                                              │
│   Open your browser to:                                                      │
│   http://localhost:5173                                                      │
│                                                                              │
│   Admin email: admin@canvas-clay.local                                       │
│                                                                              │
│   Useful commands:                                                           │
│     View logs:        docker compose -f infra/docker-compose.yml logs -f     │
│     Stop:             docker compose -f infra/docker-compose.yml down        │
│     Restart backend:  docker compose -f infra/docker-compose.yml restart     │
│                                                                              │
│                         Press any key to exit...                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Step 8: Sign In

1. Open http://localhost:5173 in your browser
2. Click **"Sign in"** in the top right
3. Enter your admin credentials:
   - **Email:** `admin@canvas-clay.local`
   - **Password:** (the password you set during setup, or check `backend/.env`)

You now have full admin access to manage users, artworks, and settings.

### Step 9: Seed Demo Data (Optional)

After signing in, visit http://localhost:5173/setup to seed demo artists and artworks.

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

### Repair Wizard

Diagnose and fix common issues:

```bash
./setup.sh
# Then press 2 for Repair
```

Or run directly:

```bash
./setup.sh --repair
```

The repair wizard scans and can auto-fix:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CANVAS & CLAY                                   │
│                             Repair Wizard                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Scanning for issues...                                                     │
│                                                                              │
│   [/] Checking Docker status...                                              │
│       [OK]  Docker installed                                                 │
│       [OK]  Docker daemon running                                            │
│       [OK]  All containers running                                           │
│                                                                              │
│   [/] Checking environment...                                                │
│       [OK]  .env file exists                                                 │
│       [OK]  SECRET_KEY set                                                   │
│       [OK]  PII_ENCRYPTION_KEY set                                           │
│       [OK]  .env syntax valid                                                │
│                                                                              │
│   [/] Checking filesystem...                                                 │
│       [OK]  uploads/ directory exists                                        │
│       [OK]  thumbnails/ directory exists                                     │
│                                                                              │
│   [/] Checking database...                                                   │
│       [OK]  Database connection OK                                           │
│       [OK]  Migrations OK                                                    │
│                                                                              │
│   [/] Checking data integrity...                                             │
│       [OK]  No orphaned files                                                │
│       [OK]  No missing file records                                          │
│       [OK]  All thumbnails present                                           │
│                                                                              │
│   ──────────────────────────────────────────────────────────────────────     │
│   No issues found!                                                           │
│                                                                              │
│                       Press any key to return...                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Checks performed:**

| Check | Auto-fixable |
|-------|--------------|
| Docker installed & running | No |
| Containers running | Yes |
| .env file exists | Yes |
| SECRET_KEY configured | Yes |
| PII_ENCRYPTION_KEY valid | Yes |
| .env syntax valid | Yes |
| uploads/ directory exists | Yes |
| Database connection | No |
| Migrations status | Yes |
| Orphaned files | Yes |
| Missing thumbnails | Yes |
| Disk space | No |
| Port availability | No |
| Container health | Yes |

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

- `docs/` - Additional technical documentation
