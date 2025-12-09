#!/bin/bash
# entrypoint script for backend container
# automatically runs database migrations on startup

set -e

echo "waiting for database to be ready..."

# wait for postgres to be ready
while ! flask db current 2>&1; do
  echo "database not ready, waiting..."
  sleep 2
done

echo "database is ready!"

if [ "${SKIP_MIGRATIONS}" = "1" ]; then
  echo "SKIP_MIGRATIONS=1 detected; skipping database migrations."
else
  # run database migrations
  echo "running database migrations..."
  
  # check for multiple heads before upgrading
  heads_output=$(flask db heads 2>&1)
  if echo "$heads_output" | grep -q "Multiple head revisions"; then
    echo "ERROR: Multiple migration heads detected!"
    echo "$heads_output"
    echo ""
    echo "To fix this, you need to create a merge migration:"
    echo "  docker exec -it canvas_backend flask db merge -m 'merge heads' heads"
    echo "  docker exec -it canvas_backend flask db upgrade head"
    exit 1
  fi
  
  flask db upgrade
fi

# Auto-import users on fresh deployment
if [ -f "/app/users.json" ]; then
  user_count=$(python3 -c "from app import app, User; app.app_context().push(); print(User.query.count())" 2>/dev/null || echo "0")

  if [ "$user_count" -le "1" ]; then
    echo "Fresh database detected with users.json present"

    if [ "${AUTO_IMPORT_USERS}" = "1" ]; then
      echo "AUTO_IMPORT_USERS=1: Importing users..."
      python3 import_users.py --input /app/users.json --keep-passwords
    else
      echo ""
      echo "=========================================="
      echo "  users.json found - import available!"
      echo "=========================================="
      echo "To import users, either:"
      echo "  1. Set AUTO_IMPORT_USERS=1 in docker-compose.yml"
      echo "  2. Run: docker exec canvas_backend python3 import_users.py --input /app/users.json --keep-passwords"
      echo ""
    fi
  fi
fi

# Seed users from env vars if configured
if [ "${SEED_USERS}" = "1" ]; then
  echo "SEED_USERS=1: Seeding users from environment..."
  python3 seed_users.py
fi

# Auto-seed demo data on fresh deployment
if [ "${AUTO_SEED_DEMO}" = "1" ]; then
  artist_count=$(python3 -c "from app import app, db, Artist; app.app_context().push(); print(Artist.query.filter_by(is_deleted=False).count())" 2>/dev/null || echo "0")

  if [ "$artist_count" = "0" ]; then
    echo "AUTO_SEED_DEMO=1: Empty database detected, seeding demo data..."
    python3 seed_demo.py
  else
    echo "AUTO_SEED_DEMO=1: Database already has data, skipping demo seed."
  fi
fi

# Auto-import images on fresh deployment
if [ -f "/app/images.zip" ]; then
  if [ "${AUTO_IMPORT_IMAGES}" = "1" ]; then
    echo "AUTO_IMPORT_IMAGES=1: Importing images..."
    python3 import_images.py --input /app/images.zip
  else
    echo ""
    echo "=========================================="
    echo "  images.zip found - import available!"
    echo "=========================================="
    echo "To import images, either:"
    echo "  1. Set AUTO_IMPORT_IMAGES=1 in docker-compose.yml"
    echo "  2. Run: docker exec canvas_backend python3 import_images.py --input /app/images.zip"
    echo ""
  fi
fi

echo "starting flask application..."
exec "$@"
