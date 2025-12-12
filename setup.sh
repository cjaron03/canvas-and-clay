#!/usr/bin/env bash
# Canvas & Clay Setup Wizard
# Full-screen TUI for setup, repair, and admin recovery
#
# Usage:
#   ./setup.sh                    # Interactive TUI mode
#   ./setup.sh --non-interactive  # Use defaults, no prompts
#   ./setup.sh --setup            # Jump directly to setup
#   ./setup.sh --repair           # Jump directly to repair
#   ./setup.sh --recover          # Jump directly to admin recovery

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
INFRA_DIR="$SCRIPT_DIR/infra"
ENV_FILE="$BACKEND_DIR/.env"
ENV_EXAMPLE="$BACKEND_DIR/.env.example"
COMPOSE_FILE="$INFRA_DIR/docker-compose.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# Box drawing characters
BOX_TL='┌'
BOX_TR='┐'
BOX_BL='└'
BOX_BR='┘'
BOX_H='─'
BOX_V='│'
BOX_LT='├'
BOX_RT='┤'

# Parse arguments
NON_INTERACTIVE=false
DIRECT_MODE=""
for arg in "$@"; do
  case $arg in
    --non-interactive) NON_INTERACTIVE=true ;;
    --setup) DIRECT_MODE="setup" ;;
    --repair) DIRECT_MODE="repair" ;;
    --recover) DIRECT_MODE="recover" ;;
  esac
done

# =============================================================================
# TUI Helper Functions
# =============================================================================

# Get terminal dimensions
get_term_size() {
  TERM_ROWS=$(tput lines)
  TERM_COLS=$(tput cols)
}

# Move cursor to position
move_to() {
  tput cup "$1" "$2"
}

# Clear screen
clear_screen() {
  clear
}

# Hide/show cursor
hide_cursor() {
  tput civis 2>/dev/null || true
}

show_cursor() {
  tput cnorm 2>/dev/null || true
}

# Enter/exit alternate screen buffer (like vim)
enter_fullscreen() {
  tput smcup 2>/dev/null || true
  hide_cursor
  clear_screen
}

exit_fullscreen() {
  show_cursor
  tput rmcup 2>/dev/null || true
}

# Cleanup on exit
cleanup() {
  show_cursor
  tput rmcup 2>/dev/null || true
  stty echo 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Print centered text
print_centered() {
  local text="$1"
  local row="${2:-}"
  get_term_size
  local col=$(( (TERM_COLS - ${#text}) / 2 ))
  [[ $col -lt 0 ]] && col=0
  if [[ -n "$row" ]]; then
    move_to "$row" "$col"
  fi
  echo -e "$text"
}

# Draw horizontal line
draw_hline() {
  local row="$1"
  local start_col="${2:-0}"
  local width="${3:-$TERM_COLS}"
  local char="${4:-$BOX_H}"
  move_to "$row" "$start_col"
  printf '%*s' "$width" '' | tr ' ' "$char"
}

# Draw a box
draw_box() {
  local top="$1"
  local left="$2"
  local height="$3"
  local width="$4"

  # Top border
  move_to "$top" "$left"
  echo -n "$BOX_TL"
  printf '%*s' "$((width-2))" '' | tr ' ' "$BOX_H"
  echo -n "$BOX_TR"

  # Sides
  for ((i=1; i<height-1; i++)); do
    move_to "$((top+i))" "$left"
    echo -n "$BOX_V"
    move_to "$((top+i))" "$((left+width-1))"
    echo -n "$BOX_V"
  done

  # Bottom border
  move_to "$((top+height-1))" "$left"
  echo -n "$BOX_BL"
  printf '%*s' "$((width-2))" '' | tr ' ' "$BOX_H"
  echo -n "$BOX_BR"
}

# Print text at position
print_at() {
  local row="$1"
  local col="$2"
  local text="$3"
  move_to "$row" "$col"
  echo -e "$text"
}

# Wait for key press
wait_key() {
  local prompt="${1:-Press any key to continue...}"
  get_term_size
  print_centered "${DIM}$prompt${RESET}" "$((TERM_ROWS-2))"
  read -rsn1
}

# Wait for specific keys
wait_for_key() {
  read -rsn1 key
  echo "$key"
}

# Spinner animation
spinner() {
  local message="$1"
  local pid="$2"
  local frames='|/-\'
  local i=0

  while kill -0 "$pid" 2>/dev/null; do
    printf "\r    [${CYAN}%c${RESET}] %s" "${frames:i++%4:1}" "$message"
    sleep 0.1
  done
  printf "\r"
}

# Print status indicator
print_status() {
  local status="$1"
  local message="$2"
  case "$status" in
    ok)   echo -e "    [${GREEN}OK${RESET}]  $message" ;;
    warn) echo -e "    [${YELLOW}!!${RESET}]  $message" ;;
    fail) echo -e "    [${RED}FAIL${RESET}] $message" ;;
    info) echo -e "    [${BLUE}--${RESET}]  $message" ;;
    spin) echo -e "    [${CYAN}/${RESET}]  $message" ;;
  esac
}

# =============================================================================
# Screen Drawing Functions
# =============================================================================

draw_header() {
  local title="${1:-CANVAS & CLAY}"
  local subtitle="${2:-}"
  get_term_size

  clear_screen
  draw_box 0 0 "$TERM_ROWS" "$TERM_COLS"

  print_centered "${BOLD}${WHITE}$title${RESET}" 3
  if [[ -n "$subtitle" ]]; then
    print_centered "${DIM}$subtitle${RESET}" 4
  fi

  # Separator line
  move_to 6 1
  echo -n "$BOX_LT"
  printf '%*s' "$((TERM_COLS-3))" '' | tr ' ' "$BOX_H"
  echo -n "$BOX_RT"
}

draw_main_menu() {
  draw_header "CANVAS & CLAY" "Local-First Digital Gallery"

  get_term_size
  local menu_top=$((TERM_ROWS/2 - 4))
  local menu_left=$((TERM_COLS/2 - 30))

  print_centered "A secure artwork management system for" 8
  print_centered "artists and collectors." 9

  # Menu box
  draw_box "$menu_top" "$menu_left" 12 60

  print_at "$((menu_top+2))" "$((menu_left+6))" "${BOLD}[1]${RESET}  Setup      ${DIM}Configure environment and start services${RESET}"
  print_at "$((menu_top+4))" "$((menu_left+6))" "${BOLD}[2]${RESET}  Repair     ${DIM}Scan for and fix common issues${RESET}"
  print_at "$((menu_top+6))" "$((menu_left+6))" "${BOLD}[3]${RESET}  Recover    ${DIM}Reset admin password (emergency)${RESET}"
  print_at "$((menu_top+8))" "$((menu_left+6))" "${BOLD}[q]${RESET}  Quit"

  print_centered "Press 1, 2, 3, or q" "$((TERM_ROWS-3))"
}

# =============================================================================
# Setup Flow
# =============================================================================

run_setup_flow() {
  local step=1
  local total_steps=5
  local issues=()

  # Pre-check: Detect existing database setup
  if docker info &>/dev/null; then
    local compose_status
    compose_status=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "")
    if echo "$compose_status" | grep -q "backend.*Up"; then
      # Show scanning animation
      draw_header "CANVAS & CLAY" "Setup"
      print_at 8 4 "Scanning for existing database..."

      local frames='|/-\'
      local i=0
      local user_count=""

      # Run database check in background (exclude bootstrap admin from count)
      local tmp_file=$(mktemp)
      local bootstrap_email
      bootstrap_email=$(grep "^BOOTSTRAP_ADMIN_EMAIL=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "admin@canvas-clay.local")
      docker exec canvas_backend python3 -c "
import os
from app import app, db
from models import init_models
User = init_models(db)[0]
bootstrap_email = '$bootstrap_email'.lower()
with app.app_context():
    # Count all users EXCEPT the bootstrap admin
    count = User.query.filter(User.email != bootstrap_email).count()
    bootstrap_exists = User.query.filter(User.email == bootstrap_email).first() is not None
    print(f'{count}|{bootstrap_exists}')
" > "$tmp_file" 2>/dev/null &
      local check_pid=$!

      # Animate while checking
      while kill -0 "$check_pid" 2>/dev/null; do
        print_at 10 4 "    [${CYAN}${frames:i++%4:1}${RESET}] Checking database..."
        sleep 0.1
      done

      # Get result
      wait "$check_pid" 2>/dev/null || true
      local result=$(cat "$tmp_file" 2>/dev/null || echo "0|False")
      rm -f "$tmp_file"

      # Parse result: "count|bootstrap_exists"
      user_count=$(echo "$result" | cut -d'|' -f1)
      local bootstrap_exists=$(echo "$result" | cut -d'|' -f2)
      [[ -z "$user_count" ]] && user_count=0

      # Clear the spinner line
      print_at 10 4 "                                        "

      if [[ "$user_count" -gt 0 ]]; then
        draw_header "CANVAS & CLAY" "Setup"
        print_at 8 4 "${GREEN}${BOLD}Database detected, no setup required!${RESET}"
        draw_hline 9 4 "$((TERM_COLS-8))" "─"

        print_at 11 4 "An existing database with ${CYAN}$user_count user(s)${RESET} was found."
        print_at 12 4 "(excluding bootstrap admin)"
        print_at 13 4 "The system appears to be already configured."

        print_at 15 4 "Services are running at:"
        print_at 16 6 "${CYAN}Frontend:${RESET} http://localhost:5173"
        print_at 17 6 "${CYAN}Backend:${RESET}  http://localhost:5001"

        local row=19

        # Show bootstrap admin status
        if [[ "$bootstrap_exists" == "True" ]]; then
          print_at "$row" 4 "${DIM}Bootstrap admin:${RESET} $bootstrap_email ${GREEN}(exists)${RESET}"
          ((row++))

          # Check for default admin password
          local admin_password
          admin_password=$(grep "^BOOTSTRAP_ADMIN_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
          if [[ "$admin_password" == "ChangeMe123" ]]; then
            print_at "$row" 4 "${YELLOW}${BOLD}WARNING:${RESET} ${YELLOW}Admin password is still the default!${RESET}"
            ((row++))
            print_at "$row" 4 "${YELLOW}Change BOOTSTRAP_ADMIN_PASSWORD in backend/.env${RESET}"
            ((row++))
          fi
        else
          print_at "$row" 4 "${DIM}Bootstrap admin:${RESET} $bootstrap_email ${YELLOW}(will be created)${RESET}"
          ((row++))
        fi

        ((row++))
        print_at "$row" 4 "${DIM}If you need to reconfigure, stop containers first:${RESET}"
        ((row++))
        print_at "$row" 6 "${DIM}docker compose -f infra/docker-compose.yml down -v${RESET}"

        get_term_size
        print_at "$((TERM_ROWS-4))" 4 "[${GREEN}C${RESET}] Continue setup anyway   [${YELLOW}R${RESET}] Return to menu"

        local key=$(wait_for_key)
        case "$key" in
          c|C) ;; # Continue with setup
          *) return 0 ;; # Return to menu
        esac
      fi
    fi
  fi

  # Step 1: Prerequisites
  draw_header "CANVAS & CLAY" "Setup"
  print_at 8 4 "${BOLD}Step $step of $total_steps: Prerequisites${RESET}"
  draw_hline 9 4 "$((TERM_COLS-8))" "─"

  local row=11

  # Check Docker
  if command -v docker &>/dev/null; then
    local docker_ver=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
    print_at "$row" 4 ""; print_status ok "Docker installed (v$docker_ver)"
  else
    print_at "$row" 4 ""; print_status fail "Docker not installed"
    issues+=("Install Docker from https://docker.com")
  fi
  ((row++))

  # Check Docker Compose
  if docker compose version &>/dev/null; then
    local compose_ver=$(docker compose version --short 2>/dev/null || echo "unknown")
    print_at "$row" 4 ""; print_status ok "Docker Compose (v$compose_ver)"
  else
    print_at "$row" 4 ""; print_status fail "Docker Compose not available"
    issues+=("Ensure Docker Compose is installed")
  fi
  ((row++))

  # Check Docker daemon
  if docker info &>/dev/null; then
    print_at "$row" 4 ""; print_status ok "Docker daemon running"
  else
    print_at "$row" 4 ""; print_status fail "Docker daemon not running"
    issues+=("Start Docker Desktop or run: sudo systemctl start docker")
  fi
  ((row++))

  # Check docker-compose.yml
  if [[ -f "$COMPOSE_FILE" ]]; then
    print_at "$row" 4 ""; print_status ok "docker-compose.yml found"
  else
    print_at "$row" 4 ""; print_status fail "docker-compose.yml not found"
    issues+=("Missing infra/docker-compose.yml - re-clone the repository")
  fi
  ((row++))

  # Check .env
  if [[ -f "$ENV_FILE" ]]; then
    print_at "$row" 4 ""; print_status ok ".env file exists"
  else
    print_at "$row" 4 ""; print_status warn ".env file missing (will be created)"
  fi
  ((row++))

  # Show issues if any critical ones
  if [[ ${#issues[@]} -gt 0 ]]; then
    ((row++))
    print_at "$row" 4 "${RED}${BOLD}Cannot proceed. Please fix these issues:${RESET}"
    for issue in "${issues[@]}"; do
      ((row++))
      print_at "$row" 6 "${YELLOW}- $issue${RESET}"
    done
    wait_key "Press any key to return to menu..."
    return 1
  fi

  wait_key
  ((step++))

  # Step 2: Environment Configuration
  setup_environment
  ((step++))

  # Step 3: Docker Build
  draw_header "CANVAS & CLAY" "Setup"
  print_at 8 4 "${BOLD}Step $step of $total_steps: Building Containers${RESET}"
  draw_hline 9 4 "$((TERM_COLS-8))" "─"

  print_at 11 4 "Building and starting Docker containers..."
  print_at 12 4 "${DIM}This may take a few minutes on first run.${RESET}"

  show_cursor
  move_to 14 4

  cd "$INFRA_DIR"

  # Run docker compose and capture exit code properly
  local build_log
  build_log=$(docker compose up --build -d 2>&1)
  local build_status=$?

  # Show last 20 lines of output
  echo "$build_log" | tail -20

  if [[ $build_status -eq 0 ]]; then
    print_at 35 4 ""; print_status ok "Containers started"
  else
    print_at 35 4 ""; print_status fail "Failed to start containers"
    print_at 36 4 "${DIM}Check logs: docker compose -f infra/docker-compose.yml logs${RESET}"
    wait_key
    return 1
  fi
  hide_cursor

  wait_key
  ((step++))

  # Step 4: Health Check
  draw_header "CANVAS & CLAY" "Setup"
  print_at 8 4 "${BOLD}Step $step of $total_steps: Health Check${RESET}"
  draw_hline 9 4 "$((TERM_COLS-8))" "─"

  print_at 11 4 "Waiting for services to be ready..."

  local max_attempts=30
  local attempt=0
  local healthy=false

  while [[ $attempt -lt $max_attempts ]]; do
    if curl -s http://localhost:5001/health &>/dev/null; then
      healthy=true
      break
    fi
    ((attempt++))
    print_at 13 4 "    Attempt $attempt/$max_attempts..."
    sleep 2
  done

  if $healthy; then
    print_at 15 4 ""; print_status ok "Backend is healthy"
    print_at 16 4 ""; print_status ok "Services are ready"
  else
    print_at 15 4 ""; print_status warn "Health check timed out"
    print_at 16 4 "${DIM}    Services may still be starting. Check logs with:${RESET}"
    print_at 17 4 "${DIM}    docker compose -f infra/docker-compose.yml logs -f${RESET}"
  fi

  wait_key
  ((step++))

  # Step 5: Complete
  draw_header "CANVAS & CLAY" "Setup Complete"

  print_at 8 4 "${GREEN}${BOLD}Setup completed successfully!${RESET}"
  draw_hline 9 4 "$((TERM_COLS-8))" "─"

  print_at 11 4 "Canvas & Clay is now running."
  print_at 13 4 "Open your browser to:"
  print_at 14 4 "${CYAN}${BOLD}http://localhost:5173/setup${RESET}"
  print_at 16 4 "Login with your admin credentials to seed demo data."

  print_at 18 4 "${DIM}Admin email: $(grep BOOTSTRAP_ADMIN_EMAIL "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo 'admin@canvas-clay.local')${RESET}"

  print_at 21 4 "${BOLD}Useful commands:${RESET}"
  print_at 22 4 "  View logs:        docker compose -f infra/docker-compose.yml logs -f"
  print_at 23 4 "  Stop:             docker compose -f infra/docker-compose.yml down"
  print_at 24 4 "  Restart backend:  docker compose -f infra/docker-compose.yml restart backend"

  wait_key "Press any key to exit..."
  return 0
}

# =============================================================================
# Environment Setup
# =============================================================================

setup_environment() {
  draw_header "CANVAS & CLAY" "Setup"
  print_at 8 4 "${BOLD}Step 2 of 5: Environment Configuration${RESET}"
  draw_hline 9 4 "$((TERM_COLS-8))" "─"

  local row=11

  if [[ -f "$ENV_FILE" ]]; then
    print_at "$row" 4 "Existing .env file found."
    ((row++))
    print_at "$row" 4 "${DIM}Keeping existing configuration.${RESET}"
    ((row+=2))
    wait_key
    return 0
  fi

  # Try to copy from template
  if [[ -f "$ENV_EXAMPLE" ]]; then
    print_at "$row" 4 "Creating .env from template..."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    print_at "$row" 4 ""; print_status ok "Created .env from .env.example"
    ((row++))
  else
    print_at "$row" 4 ""; print_status warn "No .env.example found"
    ((row++))
    print_at "$row" 4 "Generating .env from scratch..."
    ((row++))
    generate_env_from_scratch
  fi

  ((row++))

  # Generate secure keys
  print_at "$row" 4 "Generating secure keys..."
  ((row++))

  local secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
  local pii_key=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)

  if [[ -f "$ENV_FILE" ]]; then
    # Update keys in file
    if grep -q "^SECRET_KEY=" "$ENV_FILE"; then
      sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$secret_key|" "$ENV_FILE"
    else
      echo "SECRET_KEY=$secret_key" >> "$ENV_FILE"
    fi

    if grep -q "^PII_ENCRYPTION_KEY=" "$ENV_FILE"; then
      sed -i.bak "s|^PII_ENCRYPTION_KEY=.*|PII_ENCRYPTION_KEY=$pii_key|" "$ENV_FILE"
    else
      echo "PII_ENCRYPTION_KEY=$pii_key" >> "$ENV_FILE"
    fi

    rm -f "${ENV_FILE}.bak"
  fi

  print_at "$row" 4 ""; print_status ok "SECRET_KEY generated"
  ((row++))
  print_at "$row" 4 ""; print_status ok "PII_ENCRYPTION_KEY generated"
  ((row++))

  # Interactive configuration if not non-interactive
  if ! $NON_INTERACTIVE; then
    ((row++))
    show_cursor

    print_at "$row" 4 "Admin email [admin@canvas-clay.local]: "
    move_to "$row" 42
    read -r admin_email
    admin_email="${admin_email:-admin@canvas-clay.local}"

    ((row++))
    print_at "$row" 4 "Admin password: "
    move_to "$row" 20
    read -rs admin_password

    if [[ -z "$admin_password" ]]; then
      admin_password="CanvasClay$(date +%Y)!"
      ((row++))
      print_at "$row" 4 "${DIM}(Using generated password: $admin_password)${RESET}"
    fi

    hide_cursor

    # Update admin credentials
    sed -i.bak "s|^BOOTSTRAP_ADMIN_EMAIL=.*|BOOTSTRAP_ADMIN_EMAIL=$admin_email|" "$ENV_FILE"
    sed -i.bak "s|^BOOTSTRAP_ADMIN_PASSWORD=.*|BOOTSTRAP_ADMIN_PASSWORD=$admin_password|" "$ENV_FILE"
    rm -f "${ENV_FILE}.bak"
  fi

  ((row+=2))
  print_at "$row" 4 ""; print_status ok "Environment configured"

  wait_key
}

generate_env_from_scratch() {
  cat > "$ENV_FILE" << 'ENVEOF'
# Canvas & Clay Environment Configuration
# Generated by setup wizard

# Flask Configuration
SECRET_KEY=PLACEHOLDER_SECRET_KEY
FLASK_ENV=development
FLASK_DEBUG=false

# Database Configuration
DB_HOST=db
DB_PORT=5432
DB_NAME=canvas_clay
DB_USER=canvas_db
DB_PASSWORD=clay123

# Security
PII_ENCRYPTION_KEY=PLACEHOLDER_PII_KEY
ALLOW_INSECURE_COOKIES=true
SESSION_COOKIE_SECURE=false

# CORS
CORS_ORIGINS=http://localhost:5173

# Bootstrap Admin
BOOTSTRAP_ADMIN_EMAIL=admin@canvas-clay.local
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123
ENVEOF
}

# =============================================================================
# Repair Flow
# =============================================================================

run_repair_flow() {
  draw_header "CANVAS & CLAY" "Repair Wizard"

  local issues=()
  local fixable=()
  local row=8

  print_at "$row" 4 "Scanning for issues..."
  ((row+=2))

  # Check 1: Docker
  print_at "$row" 4 "[${CYAN}/${RESET}] Checking Docker status..."
  sleep 0.3

  local docker_ok=true
  ((row++))

  if command -v docker &>/dev/null; then
    print_at "$row" 8 ""; print_status ok "Docker installed"
  else
    print_at "$row" 8 ""; print_status fail "Docker not installed"
    issues+=("Docker not installed - visit https://docker.com")
    docker_ok=false
  fi
  ((row++))

  if $docker_ok && docker info &>/dev/null; then
    print_at "$row" 8 ""; print_status ok "Docker daemon running"
  elif $docker_ok; then
    print_at "$row" 8 ""; print_status fail "Docker daemon not running"
    issues+=("Start Docker Desktop or run: sudo systemctl start docker")
    docker_ok=false
  fi
  ((row++))

  # Check containers if docker is running
  if $docker_ok; then
    # Use -f flag explicitly to ensure we find the compose file
    local compose_output
    compose_output=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "")

    # Check that ALL three services are running (backend, frontend, db)
    local backend_up=false frontend_up=false db_up=false
    echo "$compose_output" | grep -q "backend.*Up" && backend_up=true
    echo "$compose_output" | grep -q "frontend.*Up" && frontend_up=true
    echo "$compose_output" | grep -q "db.*Up" && db_up=true

    if $backend_up && $frontend_up && $db_up; then
      print_at "$row" 8 ""; print_status ok "All containers running"
    elif $backend_up || $frontend_up || $db_up; then
      # Some containers running but not all
      local down_services=""
      $backend_up || down_services+="backend "
      $frontend_up || down_services+="frontend "
      $db_up || down_services+="db "
      print_at "$row" 8 ""; print_status warn "Some containers down: ${down_services}"
      fixable+=("start_containers")
      issues+=("Some containers not running: ${down_services}[auto-fixable]")
    else
      print_at "$row" 8 ""; print_status warn "Containers not running"
      fixable+=("start_containers")
      issues+=("Containers not running [auto-fixable]")
    fi
  fi
  ((row+=2))

  # Check 2: Environment
  print_at "$row" 4 "[${CYAN}/${RESET}] Checking environment..."
  sleep 0.2
  ((row++))

  if [[ -f "$ENV_FILE" ]]; then
    print_at "$row" 8 ""; print_status ok ".env file exists"
  else
    print_at "$row" 8 ""; print_status warn ".env file missing"
    fixable+=("create_env")
    issues+=(".env file missing [auto-fixable]")
  fi
  ((row++))

  if [[ -f "$ENV_FILE" ]] && grep -qE "^[[:space:]]*SECRET_KEY=.+" "$ENV_FILE" 2>/dev/null; then
    print_at "$row" 8 ""; print_status ok "SECRET_KEY set"
  elif [[ -f "$ENV_FILE" ]]; then
    print_at "$row" 8 ""; print_status warn "SECRET_KEY not set"
    fixable+=("gen_secret_key")
    issues+=("SECRET_KEY not set [auto-fixable]")
  fi
  ((row++))

  if [[ -f "$ENV_FILE" ]] && grep -qE "^[[:space:]]*PII_ENCRYPTION_KEY=.+" "$ENV_FILE" 2>/dev/null; then
    print_at "$row" 8 ""; print_status ok "PII_ENCRYPTION_KEY set"
  elif [[ -f "$ENV_FILE" ]]; then
    print_at "$row" 8 ""; print_status warn "PII_ENCRYPTION_KEY not set"
    fixable+=("gen_pii_key")
    issues+=("PII_ENCRYPTION_KEY not set [auto-fixable]")
  fi
  ((row++))

  # Check for malformed .env lines (non-empty, non-comment lines without =)
  if [[ -f "$ENV_FILE" ]]; then
    local malformed_lines
    malformed_lines=$(grep -n "^[^#]" "$ENV_FILE" 2>/dev/null | grep -v "=" | head -5 || true)
    if [[ -n "$malformed_lines" ]]; then
      local line_nums=$(echo "$malformed_lines" | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')
      print_at "$row" 8 ""; print_status warn "Malformed .env lines: $line_nums"
      fixable+=("fix_malformed_env")
      issues+=("Malformed .env syntax on line(s) $line_nums [auto-fixable]")
    else
      print_at "$row" 8 ""; print_status ok ".env syntax valid"
    fi
  fi
  ((row+=2))

  # Check 3: Filesystem
  print_at "$row" 4 "[${CYAN}/${RESET}] Checking filesystem..."
  sleep 0.2
  ((row++))

  if [[ -d "$BACKEND_DIR/uploads" ]]; then
    print_at "$row" 8 ""; print_status ok "uploads/ directory exists"
  else
    print_at "$row" 8 ""; print_status warn "uploads/ directory missing"
    fixable+=("create_uploads_dir")
    issues+=("uploads/ directory missing [auto-fixable]")
  fi
  ((row++))

  if [[ -d "$BACKEND_DIR/uploads/thumbnails" ]]; then
    print_at "$row" 8 ""; print_status ok "thumbnails/ directory exists"
  else
    print_at "$row" 8 ""; print_status warn "thumbnails/ directory missing"
    fixable+=("create_thumbnails_dir")
    issues+=("thumbnails/ directory missing [auto-fixable]")
  fi
  ((row+=2))

  # Check 4: Database (if containers running)
  local compose_status
  compose_status=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "")
  if $docker_ok && echo "$compose_status" | grep -q "backend.*Up"; then
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking database..."
    sleep 0.2
    ((row++))

    if docker exec canvas_backend python3 -c "from app import app, db; app.app_context().push(); db.session.execute(db.text('SELECT 1'))" &>/dev/null; then
      print_at "$row" 8 ""; print_status ok "Database connection OK"
    else
      print_at "$row" 8 ""; print_status fail "Database connection failed"
      issues+=("Database connection failed - check DB credentials in .env")
    fi
    ((row++))

    # Check migrations (use -T to prevent TTY output bleeding through)
    local heads_output=$(docker exec canvas_backend flask db heads 2>&1 || echo "migration_check_failed")
    if echo "$heads_output" | grep -q "Multiple head"; then
      print_at "$row" 8 ""; print_status warn "Multiple migration heads detected"
      issues+=("Multiple migration heads - run: docker exec canvas_backend flask db merge -m 'merge' heads")
    elif echo "$heads_output" | grep -q "migration_check_failed"; then
      print_at "$row" 8 ""; print_status warn "Could not check migrations (database may still be initializing)"
    else
      print_at "$row" 8 ""; print_status ok "Migrations OK"
    fi
    ((row+=2))

    # Check 5: Data integrity (comprehensive scan)
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking data integrity..."
    sleep 0.2
    ((row++))

    # Run comprehensive scan using repair_scan.py (bash-friendly output)
    local scan_output
    scan_output=$(docker exec canvas_backend python3 repair_scan.py 2>/dev/null || echo "")

    # Initialize defaults
    local ORPHANED_COUNT=0 MISSING_FILES_COUNT=0 MISSING_THUMBNAILS_COUNT=0
    local ORPHANED_SCAN_SKIPPED=false ORPHANED_SKIP_REASON=""
    local DISK_SPACE_OK=unknown DISK_SPACE_FREE_MB=0
    local MIGRATION_STATUS=unknown MIGRATION_HEADS=0
    local PII_KEY_STATUS=unknown PII_KEY_SOURCE=none

    # Parse the key=value output safely
    if [[ -n "$scan_output" ]]; then
      while IFS='=' read -r key value; do
        case "$key" in
          ORPHANED_COUNT) ORPHANED_COUNT="$value" ;;
          ORPHANED_SCAN_SKIPPED) ORPHANED_SCAN_SKIPPED="$value" ;;
          ORPHANED_SKIP_REASON) ORPHANED_SKIP_REASON="$value" ;;
          MISSING_FILES_COUNT) MISSING_FILES_COUNT="$value" ;;
          MISSING_THUMBNAILS_COUNT) MISSING_THUMBNAILS_COUNT="$value" ;;
          DISK_SPACE_OK) DISK_SPACE_OK="$value" ;;
          DISK_SPACE_FREE_MB) DISK_SPACE_FREE_MB="$value" ;;
          MIGRATION_STATUS) MIGRATION_STATUS="$value" ;;
          MIGRATION_HEADS) MIGRATION_HEADS="$value" ;;
          PII_KEY_STATUS) PII_KEY_STATUS="$value" ;;
          PII_KEY_SOURCE) PII_KEY_SOURCE="$value" ;;
        esac
      done <<< "$scan_output"
    fi

    # Report orphaned files
    if [[ "$ORPHANED_SCAN_SKIPPED" == "true" ]]; then
      print_at "$row" 8 ""; print_status info "Orphan scan skipped (safety check)"
      ((row++))
      print_at "$row" 8 ""; print_status info "${DIM}$ORPHANED_SKIP_REASON${RESET}"
    elif [[ "$ORPHANED_COUNT" -gt 0 ]]; then
      print_at "$row" 8 ""; print_status warn "$ORPHANED_COUNT orphaned files found"
      fixable+=("fix_orphaned_files")
      issues+=("$ORPHANED_COUNT orphaned files [auto-fixable]")
    else
      print_at "$row" 8 ""; print_status ok "No orphaned files"
    fi
    ((row++))

    # Report missing files (NOT auto-fixable - requires manual review)
    if [[ "$MISSING_FILES_COUNT" -gt 0 ]]; then
      print_at "$row" 8 ""; print_status warn "$MISSING_FILES_COUNT missing file records"
      # Don't add to fixable - this requires manual intervention
      # Missing files = DB records pointing to files not on disk
      # Could be: imported data without files, deleted files, or path issues
      issues+=("$MISSING_FILES_COUNT DB records point to missing files (review manually: may be imported data, deleted files, or sync issues)")
    else
      print_at "$row" 8 ""; print_status ok "No missing file records"
    fi
    ((row++))

    # Report missing thumbnails
    if [[ "$MISSING_THUMBNAILS_COUNT" -gt 0 ]]; then
      print_at "$row" 8 ""; print_status warn "$MISSING_THUMBNAILS_COUNT missing thumbnails"
      fixable+=("fix_missing_thumbnails")
      issues+=("$MISSING_THUMBNAILS_COUNT missing thumbnails [auto-fixable]")
    else
      print_at "$row" 8 ""; print_status ok "All thumbnails present"
    fi
    ((row+=2))

    # Check 6: Disk space
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking disk space..."
    sleep 0.15
    ((row++))

    if [[ "$DISK_SPACE_OK" == "false" ]]; then
      print_at "$row" 8 ""; print_status warn "Low disk space (${DISK_SPACE_FREE_MB}MB free)"
      issues+=("Low disk space - free up space in uploads/")
    elif [[ "$DISK_SPACE_OK" == "true" ]]; then
      print_at "$row" 8 ""; print_status ok "Disk space OK (${DISK_SPACE_FREE_MB}MB free)"
    else
      print_at "$row" 8 ""; print_status info "Could not check disk space"
    fi
    ((row+=2))

    # Check 7: Migration status (from scan results)
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking migration status..."
    sleep 0.15
    ((row++))

    if [[ "$MIGRATION_STATUS" == "multiple_heads" ]]; then
      print_at "$row" 8 ""; print_status warn "Multiple migration heads detected ($MIGRATION_HEADS heads)"
      fixable+=("fix_migrations")
      issues+=("Multiple migration heads [auto-fixable]")
    elif [[ "$MIGRATION_STATUS" == "ok" ]]; then
      print_at "$row" 8 ""; print_status ok "Migrations OK"
    else
      print_at "$row" 8 ""; print_status info "Could not check migrations"
    fi
    ((row+=2))

    # Check 8: Port availability
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking port availability..."
    sleep 0.15
    ((row++))

    local ports_ok=true
    for port in 5001 5173 5432; do
      # Check if port is in use by non-Docker process
      if command -v lsof &>/dev/null; then
        local port_user=$(lsof -i :"$port" -sTCP:LISTEN 2>/dev/null | grep -v "^COMMAND\|docker\|com.dock" | head -1 || true)
        if [[ -n "$port_user" ]]; then
          local proc_name=$(echo "$port_user" | awk '{print $1}')
          print_at "$row" 8 ""; print_status warn "Port $port in use by: $proc_name"
          issues+=("Port $port blocked by $proc_name [manual fix]")
          ports_ok=false
          ((row++))
        fi
      fi
    done
    if $ports_ok; then
      print_at "$row" 8 ""; print_status ok "All ports available"
    fi
    ((row+=2))

    # Check 9: Container health
    print_at "$row" 4 "[${CYAN}/${RESET}] Checking container health..."
    sleep 0.15
    ((row++))

    local unhealthy_count=0
    local container_health=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "")
    if echo "$container_health" | grep -qi "unhealthy"; then
      unhealthy_count=$(echo "$container_health" | grep -ci "unhealthy" || echo "0")
    fi

    if [[ "$unhealthy_count" -gt 0 ]]; then
      print_at "$row" 8 ""; print_status warn "$unhealthy_count unhealthy container(s)"
      fixable+=("fix_stale_containers")
      issues+=("$unhealthy_count unhealthy containers [auto-fixable]")
    else
      print_at "$row" 8 ""; print_status ok "All containers healthy"
    fi
    ((row+=2))

    # Check 10: PII Encryption Key validation
    print_at "$row" 4 "[${CYAN}/${RESET}] Validating PII encryption key..."
    sleep 0.15
    ((row++))

    case "$PII_KEY_STATUS" in
      ok)
        print_at "$row" 8 ""; print_status ok "PII encryption key valid (source: $PII_KEY_SOURCE)"
        ;;
      missing)
        print_at "$row" 8 ""; print_status fail "PII encryption key missing"
        fixable+=("gen_pii_key")
        issues+=("PII_ENCRYPTION_KEY not configured [auto-fixable]")
        ;;
      empty)
        print_at "$row" 8 ""; print_status warn "PII encryption key is empty"
        fixable+=("gen_pii_key")
        issues+=("PII_ENCRYPTION_KEY is empty [auto-fixable]")
        ;;
      placeholder)
        print_at "$row" 8 ""; print_status warn "PII encryption key is a placeholder value"
        fixable+=("gen_pii_key")
        issues+=("PII_ENCRYPTION_KEY is placeholder [auto-fixable]")
        ;;
      too_short)
        print_at "$row" 8 ""; print_status warn "PII encryption key too short (<16 chars)"
        fixable+=("gen_pii_key")
        issues+=("PII_ENCRYPTION_KEY too short [auto-fixable]")
        ;;
      invalid|error)
        print_at "$row" 8 ""; print_status fail "PII encryption key failed validation"
        fixable+=("gen_pii_key")
        issues+=("PII_ENCRYPTION_KEY invalid [auto-fixable]")
        ;;
      *)
        print_at "$row" 8 ""; print_status info "Could not validate PII encryption key"
        ;;
    esac
    ((row+=2))
  fi

  # Summary
  draw_hline "$row" 4 "$((TERM_COLS-8))" "─"
  ((row++))

  if [[ ${#issues[@]} -eq 0 ]]; then
    print_at "$row" 4 "${GREEN}${BOLD}No issues found!${RESET}"
    wait_key "Press any key to return..."
    return 0
  fi

  print_at "$row" 4 "Found ${YELLOW}${#issues[@]}${RESET} issues."
  ((row+=2))

  if [[ ${#fixable[@]} -gt 0 ]]; then
    print_at "$row" 4 "[${GREEN}F${RESET}] Fix All (${#fixable[@]} auto-fixable)   [${YELLOW}S${RESET}] Skip   [${RED}Q${RESET}] Quit"

    local key=$(wait_for_key)
    case "$key" in
      f|F) apply_fixes "${fixable[@]}" ;;
      *) return 0 ;;
    esac
  else
    print_at "$row" 4 "No auto-fixable issues. Please fix manually:"
    ((row++))
    for issue in "${issues[@]}"; do
      ((row++))
      print_at "$row" 6 "${DIM}- $issue${RESET}"
    done
    wait_key
  fi
}

apply_fixes() {
  local fixes=("$@")

  draw_header "CANVAS & CLAY" "Applying Fixes"
  local row=8

  for fix in "${fixes[@]}"; do
    case "$fix" in
      create_env)
        print_at "$row" 4 "Creating .env file..."
        generate_env_from_scratch
        print_at "$row" 4 ""; print_status ok "Created .env file"
        ;;
      gen_secret_key)
        print_at "$row" 4 "Generating SECRET_KEY..."
        local key=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
        if grep -q "^SECRET_KEY=" "$ENV_FILE"; then
          sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$key|" "$ENV_FILE"
        else
          echo "SECRET_KEY=$key" >> "$ENV_FILE"
        fi
        rm -f "${ENV_FILE}.bak"
        print_at "$row" 4 ""; print_status ok "Generated SECRET_KEY"
        ;;
      gen_pii_key)
        print_at "$row" 4 "Generating PII_ENCRYPTION_KEY..."
        local key=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)
        if grep -q "^PII_ENCRYPTION_KEY=" "$ENV_FILE"; then
          sed -i.bak "s|^PII_ENCRYPTION_KEY=.*|PII_ENCRYPTION_KEY=$key|" "$ENV_FILE"
        else
          echo "PII_ENCRYPTION_KEY=$key" >> "$ENV_FILE"
        fi
        rm -f "${ENV_FILE}.bak"
        print_at "$row" 4 ""; print_status ok "Generated PII_ENCRYPTION_KEY"
        ;;
      fix_malformed_env)
        print_at "$row" 4 "Removing malformed .env lines..."
        # Remove lines that are not comments, not empty, and don't contain =
        local temp_file=$(mktemp)
        while IFS= read -r line || [[ -n "$line" ]]; do
          # Keep empty lines, comments, and lines with =
          if [[ -z "$line" || "$line" =~ ^[[:space:]]*# || "$line" =~ = ]]; then
            echo "$line" >> "$temp_file"
          fi
        done < "$ENV_FILE"
        mv "$temp_file" "$ENV_FILE"
        print_at "$row" 4 ""; print_status ok "Removed malformed lines"
        ;;
      create_uploads_dir)
        print_at "$row" 4 "Creating uploads/ directory..."
        mkdir -p "$BACKEND_DIR/uploads/artworks"
        print_at "$row" 4 ""; print_status ok "Created uploads/ directory"
        ;;
      create_thumbnails_dir)
        print_at "$row" 4 "Creating thumbnails/ directory..."
        mkdir -p "$BACKEND_DIR/uploads/thumbnails"
        print_at "$row" 4 ""; print_status ok "Created thumbnails/ directory"
        ;;
      start_containers)
        print_at "$row" 4 "Starting containers..."
        cd "$INFRA_DIR"
        docker compose up -d &>/dev/null
        print_at "$row" 4 ""; print_status ok "Started containers"
        ;;
      fix_orphaned_files)
        print_at "$row" 4 "Removing orphaned files..."
        docker exec canvas_backend python3 repair_checks.py --fix-orphans &>/dev/null
        print_at "$row" 4 ""; print_status ok "Removed orphaned files"
        ;;
      fix_missing_files)
        print_at "$row" 4 "Cleaning missing file records..."
        docker exec canvas_backend python3 repair_checks.py --fix-missing &>/dev/null
        print_at "$row" 4 ""; print_status ok "Cleaned missing file records"
        ;;
      fix_missing_thumbnails)
        print_at "$row" 4 "Regenerating thumbnails..."
        docker exec canvas_backend python3 repair_checks.py --fix-thumbnails &>/dev/null
        print_at "$row" 4 ""; print_status ok "Regenerated thumbnails"
        ;;
      fix_migrations)
        print_at "$row" 4 "Merging migration heads..."
        docker exec canvas_backend flask db merge -m "auto-merge by repair wizard" heads &>/dev/null || true
        docker exec canvas_backend flask db upgrade &>/dev/null || true
        print_at "$row" 4 ""; print_status ok "Merged migration heads"
        ;;
      fix_stale_containers)
        print_at "$row" 4 "Recreating unhealthy containers..."
        cd "$INFRA_DIR"
        docker compose down &>/dev/null
        docker compose up -d &>/dev/null
        print_at "$row" 4 ""; print_status ok "Recreated containers"
        ;;
    esac
    ((row++))
  done

  ((row++))
  print_at "$row" 4 "${GREEN}${BOLD}All fixes applied!${RESET}"

  wait_key
}

# =============================================================================
# Recovery Flow
# =============================================================================

run_recover_flow() {
  draw_header "CANVAS & CLAY" "Admin Recovery"

  local row=8

  print_at "$row" 4 "${BOLD}Emergency Admin Password Reset${RESET}"
  ((row++))
  draw_hline "$row" 4 "$((TERM_COLS-8))" "─"
  ((row+=2))

  print_at "$row" 4 "This tool resets the bootstrap admin password."
  ((row++))
  print_at "$row" 4 "${DIM}Use this when recovering from a backup where credentials are unknown.${RESET}"
  ((row+=2))

  # Check if backend container is running
  print_at "$row" 4 "[${CYAN}/${RESET}] Checking backend container..."
  sleep 0.3

  local compose_status
  compose_status=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "")

  if ! echo "$compose_status" | grep -q "backend.*Up"; then
    ((row++))
    print_at "$row" 4 ""; print_status fail "Backend container is not running"
    ((row+=2))
    print_at "$row" 4 "Start the containers first:"
    ((row++))
    print_at "$row" 6 "${DIM}docker compose -f infra/docker-compose.yml up -d${RESET}"
    ((row++))
    print_at "$row" 4 "Or run ${BOLD}[1] Setup${RESET} from the main menu."
    wait_key "Press any key to return to menu..."
    return 1
  fi

  ((row++))
  print_at "$row" 4 ""; print_status ok "Backend container is running"
  ((row+=2))

  print_at "$row" 4 "${YELLOW}${BOLD}WARNING:${RESET} This will reset the admin password."
  ((row++))
  print_at "$row" 4 "Continue? [y/N]: "

  show_cursor
  local confirm
  read -rsn1 confirm
  hide_cursor

  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    ((row+=2))
    print_at "$row" 4 "Aborted."
    wait_key "Press any key to return to menu..."
    return 0
  fi

  # Clear screen and run the recovery script
  draw_header "CANVAS & CLAY" "Admin Recovery"
  print_at 8 4 "Running recovery script..."
  print_at 9 4 "${DIM}Follow the prompts below.${RESET}"

  show_cursor
  move_to 11 0

  # Run the script interactively (it handles its own prompts)
  docker compose -f "$COMPOSE_FILE" exec backend python3 scripts/reset_admin.py

  local exit_code=$?

  hide_cursor

  if [[ $exit_code -eq 0 ]]; then
    get_term_size
    print_at "$((TERM_ROWS-4))" 4 "${GREEN}${BOLD}Password reset complete!${RESET}"
  else
    get_term_size
    print_at "$((TERM_ROWS-4))" 4 "${RED}${BOLD}Password reset failed.${RESET}"
  fi

  wait_key "Press any key to return to menu..."
  return $exit_code
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Non-interactive mode
  if $NON_INTERACTIVE; then
    echo "Running in non-interactive mode..."

    # Create .env if missing
    if [[ ! -f "$ENV_FILE" ]]; then
      if [[ -f "$ENV_EXAMPLE" ]]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
      else
        generate_env_from_scratch
      fi

      # Generate keys
      local secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
      local pii_key=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)
      sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$secret_key|" "$ENV_FILE"
      sed -i.bak "s|^PII_ENCRYPTION_KEY=.*|PII_ENCRYPTION_KEY=$pii_key|" "$ENV_FILE"
      rm -f "${ENV_FILE}.bak"
    fi

    # Start containers
    cd "$INFRA_DIR"
    docker compose up --build -d

    echo "Setup complete. Visit http://localhost:5173/setup"
    exit 0
  fi

  # Direct mode
  if [[ -n "$DIRECT_MODE" ]]; then
    enter_fullscreen
    case "$DIRECT_MODE" in
      setup) run_setup_flow ;;
      repair) run_repair_flow ;;
      recover) run_recover_flow ;;
    esac
    exit_fullscreen
    exit 0
  fi

  # Interactive TUI mode
  enter_fullscreen

  while true; do
    draw_main_menu

    local key=$(wait_for_key)
    case "$key" in
      1) run_setup_flow ;;
      2) run_repair_flow ;;
      3) run_recover_flow ;;
      q|Q) break ;;
    esac
  done

  exit_fullscreen
}

main "$@"
