#!/bin/bash
# entrypoint script for backend container
# automatically runs database migrations on startup

set -e

echo "waiting for database to be ready..."

# wait for postgres to be ready
while ! flask db current >/dev/null 2>&1; do
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

echo "starting flask application..."
exec "$@"
