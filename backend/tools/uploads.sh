#!/usr/bin/env bash
# Interactive helper for admin bulk uploads inside the backend container.
# Usage (inside container):
#   bash /app/tools/uploads.sh /app/path/to/bulk.zip
# Preview steps without running:
#   bash /app/tools/uploads.sh --preview
# Usage (from host):
#   docker compose -f infra/docker-compose.yml exec backend bash /app/tools/uploads.sh /app/path/to/bulk.zip

set -euo pipefail

GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
BOLD="\033[1m"
RESET="\033[0m"

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

show_preview() {
  echo -e "${BOLD}Uploader wizard steps:${RESET}"
  echo "1) Ask for API base URL"
  echo "2) Check API health"
  echo "3) Ask for zip path (images only)"
  echo "4) Login as admin (CSRF + session)"
  echo "5) List artists; choose existing or create new user->promote->create artist->assign"
  echo "6) Choose storage ID"
  echo "7) Choose artwork distribution (single/per-file) + titles"
  echo "8) Build manifest and call /api/admin/bulk-upload"
  echo "Type 'exit' at any prompt to cancel."
}

spinner() {
  local msg="$1"
  local pid
  ( sleep 1 ) &
  pid=$!
  local frames='|/-\'
  local i=0
  printf "%s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s [%c]" "$msg" "${frames:i++%${#frames}:1}"
    sleep 0.1
  done
  printf "\r%s [${GREEN}${ICON_OK:-✓}${RESET}]\n" "$msg"
}

ICON_OK="✓"
ICON_FAIL="✗"

# Preview mode
if [[ "${1:-}" == "--preview" ]]; then
  show_preview
  exit 0
fi

# Resolve zip path
zip_path="${1:-}"
if [[ -z "$zip_path" ]]; then
  zip_path=$(prompt "Path to zip (e.g., /app/bulk_upload.zip): ")
fi

if [[ ! -f "$zip_path" ]]; then
  echo -e "${RED}Zip not found at $zip_path. Ensure it exists inside the container (e.g., under /app).${RESET}" >&2
  exit 1
fi

base_url=$(prompt "API base URL [http://backend:5000]: " "http://backend:5000")

echo -e "${CYAN}Starting interactive uploader (type 'exit' at any prompt to cancel)...${RESET}"

# Health check (python/requests based)
printf "Checking API health at %s ... " "$base_url"
health_status=$(python3 - <<'PY' "$base_url" 2>/dev/null
import sys, json, requests
base = sys.argv[1]
try:
    r = requests.get(f"{base}/health", timeout=5)
    if r.status_code == 200:
        data = r.json()
        if data.get("status") == "healthy":
            print("healthy")
        else:
            print("degraded")
    else:
        print("unreachable")
except Exception:
    print("unreachable")
PY
)
if [[ "$health_status" == "healthy" ]]; then
  echo -e "${GREEN}${ICON_OK}${RESET} healthy"
elif [[ "$health_status" == "degraded" ]]; then
  echo -e "${YELLOW}${ICON_FAIL}${RESET} degraded (continuing)"
else
  echo -e "${YELLOW}${ICON_FAIL}${RESET} unreachable (continuing)"
fi

cmd=(python cli_bulk_upload.py --zip "$zip_path" --base-url "$base_url" --interactive)
echo -e "${CYAN}Running:${RESET} ${cmd[*]}"
"${cmd[@]}"
