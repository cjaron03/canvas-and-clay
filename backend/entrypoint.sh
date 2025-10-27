#!/bin/sh

echo "waiting for database to be ready..."
until python -c "import psycopg2; import os; psycopg2.connect(os.getenv('DATABASE_URL'))" 2>/dev/null; do
  echo "database not ready yet, retrying in 2 seconds..."
  sleep 2
done
echo "database is ready!"

echo "running database migrations..."
flask db upgrade

echo "starting flask application..."
exec "$@"

