#!/usr/bin/env bash
# Interactive helper for admin bulk uploads inside the backend container.
# Usage (inside container):
#   bash /app/tools/uploads.sh /app/path/to/bulk.zip
# Usage (from host):
#   docker compose -f infra/docker-compose.yml exec backend bash /app/tools/uploads.sh /app/path/to/bulk.zip

set -euo pipefail

prompt() {
  local msg="$1"
  local default_val="${2:-}"
  local input=""
  read -r -p "$msg" input || true
  if [[ -z "$input" && -n "$default_val" ]]; then
    echo "$default_val"
  else
    echo "$input"
  fi
}

# Resolve zip path
zip_path="${1:-}"
if [[ -z "$zip_path" ]]; then
  zip_path=$(prompt "Path to zip (e.g., /app/bulk_upload.zip): ")
fi

if [[ ! -f "$zip_path" ]]; then
  echo "Zip not found at $zip_path. Ensure it exists inside the container (e.g., under /app)." >&2
  exit 1
fi

# Admin credentials
admin_email=$(prompt "Admin email: ")
if [[ -z "$admin_email" ]]; then
  echo "Admin email is required." >&2
  exit 1
fi

echo -n "Admin password: "
stty -echo
read -r admin_password || true
stty echo
echo ""
if [[ -z "$admin_password" ]]; then
  echo "Admin password is required." >&2
  exit 1
fi

# API base
base_url=$(prompt "API base URL [http://backend:5000]: " "http://backend:5000")

# Auto-manifest options
auto_answer=$(prompt "Auto-generate manifest if missing? [Y/n]: " "Y")
auto_flag=""
if [[ "$auto_answer" =~ ^[Yy] ]]; then
  auto_flag="--auto-manifest"
fi

storage_id=$(prompt "Default storage ID for auto-manifest [STOR001]: " "STOR001")
artist_email=$(prompt "Artist email for auto-manifest (optional, Enter to skip): ")
artist_name=$(prompt "Artist name for auto-manifest [Auto Uploader]: " "Auto Uploader")

cmd=(python cli_bulk_upload.py
  --zip "$zip_path"
  --admin-email "$admin_email"
  --admin-password "$admin_password"
  --base-url "$base_url"
)

if [[ -n "$auto_flag" ]]; then
  cmd+=("$auto_flag" --default-storage "$storage_id")
  if [[ -n "$artist_email" ]]; then
    cmd+=(--artist-email "$artist_email")
  fi
  if [[ -n "$artist_name" ]]; then
    cmd+=(--artist-name "$artist_name")
  fi
fi

echo "Running: ${cmd[*]}"
"${cmd[@]}"
