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

# run database migrations
echo "running database migrations..."
flask db upgrade

echo "starting flask application..."
exec "$@"

