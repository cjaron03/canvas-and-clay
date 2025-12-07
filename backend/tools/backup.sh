#!/usr/bin/env bash
# Interactive backup and restore wizard for Canvas & Clay.
# Usage (inside container):
#   bash /app/tools/backup.sh
# Usage (from host):
#   docker compose -f infra/docker-compose.yml exec backend bash /app/tools/backup.sh

set -euo pipefail

GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

ICON_OK="✓"
ICON_FAIL="✗"

# Change to backend directory
cd /app

# Check if we're in the right place
if [[ ! -f "backup.py" ]]; then
  echo -e "${RED}Error: backup.py not found.${RESET}" >&2
  echo -e "${DIM}Make sure you're running this from the backend container.${RESET}" >&2
  exit 1
fi

# Optional: Health check
if [[ -f "app.py" ]]; then
  printf "Checking database connection... "
  health_status=$(python3 - <<'PY' 2>/dev/null || echo "unknown"
import sys
try:
    from app import app, db
    with app.app_context():
        db.session.execute(db.text("SELECT 1"))
    print("ready")
except Exception as e:
    print(f"error: {e}")
PY
  )
  if [[ "$health_status" == "ready" ]]; then
    echo -e "${GREEN}${ICON_OK}${RESET} ready"
  else
    echo -e "${YELLOW}${ICON_FAIL}${RESET} $health_status"
    echo -e "${DIM}Continuing anyway...${RESET}"
  fi
fi

echo ""
echo -e "${BOLD}Canvas & Clay Backup/Restore Wizard${RESET}"
echo "======================================"
echo ""
echo "What would you like to do?"
echo ""
echo "  1) Create a full backup (database + photos)"
echo "  2) Create a database-only backup"
echo "  3) Create a photos-only backup"
echo "  4) List available backups"
echo "  5) Restore from a backup"
echo "  6) Exit"
echo ""

read -p "Enter choice [1-6]: " choice

case $choice in
  1)
    echo ""
    echo -e "${CYAN}Creating full backup...${RESET}"
    python3 backup.py
    ;;
  2)
    echo ""
    echo -e "${CYAN}Creating database-only backup...${RESET}"
    python3 backup.py --db-only
    ;;
  3)
    echo ""
    echo -e "${CYAN}Creating photos-only backup...${RESET}"
    python3 backup.py --photos-only
    ;;
  4)
    echo ""
    echo -e "${CYAN}Available backups:${RESET}"
    echo ""
    if [[ -d "/app/backups" ]]; then
      ls -lh /app/backups/*.tar.gz 2>/dev/null || echo "No backups found."
    else
      echo "Backups directory not found."
    fi
    ;;
  5)
    echo ""
    echo -e "${CYAN}Available backups:${RESET}"
    echo ""
    if [[ -d "/app/backups" ]]; then
      backups=($(ls /app/backups/*.tar.gz 2>/dev/null || true))
      if [[ ${#backups[@]} -eq 0 ]]; then
        echo "No backups found."
        exit 0
      fi

      for i in "${!backups[@]}"; do
        filename=$(basename "${backups[$i]}")
        size=$(du -h "${backups[$i]}" | cut -f1)
        echo "  $((i+1))) $filename ($size)"
      done

      echo ""
      read -p "Enter backup number to restore (or 0 to cancel): " backup_num

      if [[ "$backup_num" == "0" ]]; then
        echo "Cancelled."
        exit 0
      fi

      if [[ "$backup_num" -lt 1 ]] || [[ "$backup_num" -gt ${#backups[@]} ]]; then
        echo -e "${RED}Invalid selection.${RESET}"
        exit 1
      fi

      selected_backup="${backups[$((backup_num-1))]}"
      echo ""
      echo -e "${YELLOW}Selected: $(basename "$selected_backup")${RESET}"
      echo ""
      echo -e "${RED}${BOLD}WARNING: This will replace your current data!${RESET}"
      read -p "Type 'RESTORE' to confirm: " confirm

      if [[ "$confirm" != "RESTORE" ]]; then
        echo "Cancelled."
        exit 0
      fi

      echo ""
      echo -e "${CYAN}Starting restore...${RESET}"
      python3 restore.py --input "$selected_backup" --force
    else
      echo "Backups directory not found."
    fi
    ;;
  6)
    echo "Goodbye!"
    exit 0
    ;;
  *)
    echo -e "${RED}Invalid choice.${RESET}"
    exit 1
    ;;
esac

echo ""
echo -e "${GREEN}${ICON_OK} Done!${RESET}"
