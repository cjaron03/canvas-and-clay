#!/usr/bin/env bash
# Host-side convenience wrapper to launch the interactive uploader inside the backend container.
# Usage:
#   ./upload.sh path/to/zip
# Preview only:
#   ./upload.sh --preview

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ZIP_PATH="${1:-}"

# Preview passthrough
if [[ "$ZIP_PATH" == "--preview" ]]; then
  docker compose -f "$ROOT/infra/docker-compose.yml" exec backend bash /app/tools/uploads.sh --preview
  exit 0
fi

if [[ -z "$ZIP_PATH" ]]; then
  echo "Usage: ./upload.sh path/to/zip" >&2
  exit 1
fi

# Resolve to absolute path
if [[ "$ZIP_PATH" != /* ]]; then
  ZIP_PATH="$ROOT/$ZIP_PATH"
fi

if [[ ! -f "$ZIP_PATH" ]]; then
  echo "Zip not found at $ZIP_PATH" >&2
  exit 1
fi

# Map host path to container path (backend volume is mounted at /app)
CONTAINER_ZIP="$ZIP_PATH"
if [[ "$ZIP_PATH" == "$ROOT"/backend/* ]]; then
  CONTAINER_ZIP="/app/${ZIP_PATH#"$ROOT"/backend/}"
fi

COMPOSE_FILE="$ROOT/infra/docker-compose.yml"
if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "docker-compose file not found at $COMPOSE_FILE" >&2
  exit 1
fi

echo "Launching uploader inside backend container with zip: $CONTAINER_ZIP"
exec docker compose -f "$COMPOSE_FILE" exec backend bash /app/tools/uploads.sh "$CONTAINER_ZIP"
