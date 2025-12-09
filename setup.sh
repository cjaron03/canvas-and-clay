#!/usr/bin/env bash
# Canvas & Clay Setup Wizard
# Interactive setup script for new installations.
#
# Usage:
#   ./setup.sh                  # Interactive mode
#   ./setup.sh --non-interactive  # Use defaults, no prompts
#
# This script:
#   1. Checks Docker prerequisites
#   2. Creates .env from .env.example if needed
#   3. Generates secure cryptographic keys
#   4. Launches Docker containers
#   5. Displays setup completion instructions

set -euo pipefail

# Colors and formatting
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

ICON_OK="[OK]"
ICON_FAIL="[FAIL]"
ICON_WARN="[!]"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
INFRA_DIR="$SCRIPT_DIR/infra"
ENV_FILE="$BACKEND_DIR/.env"
ENV_EXAMPLE="$BACKEND_DIR/.env.example"

# Parse arguments
NON_INTERACTIVE=false
for arg in "$@"; do
  case $arg in
    --non-interactive)
      NON_INTERACTIVE=true
      shift
      ;;
  esac
done

# Helper function for prompts
prompt() {
  local message="$1"
  local default="$2"
  local result

  if $NON_INTERACTIVE; then
    result="$default"
  else
    read -p "$message [$default]: " result
    result="${result:-$default}"
  fi
  echo "$result"
}

# Helper function for yes/no prompts
confirm() {
  local message="$1"
  local default="${2:-y}"
  local result

  if $NON_INTERACTIVE; then
    result="$default"
  else
    read -p "$message [${default}]: " result
    result="${result:-$default}"
  fi

  [[ "${result,,}" == "y" || "${result,,}" == "yes" ]]
}

# Display welcome banner
show_banner() {
  echo ""
  echo -e "${BOLD}"
  echo "  +--------------------------------------------+"
  echo "  |                                            |"
  echo "  |           CANVAS & CLAY                    |"
  echo "  |      Local-First Digital Gallery           |"
  echo "  |                                            |"
  echo "  |  A secure artwork management system for    |"
  echo "  |  artists and collectors.                   |"
  echo "  |                                            |"
  echo "  +--------------------------------------------+"
  echo -e "${RESET}"
  echo ""
  echo "  Welcome to Canvas & Clay setup."
  echo "  This wizard will configure your environment and prepare"
  echo "  the database for first use."
  echo ""
}

# Check prerequisites
check_prerequisites() {
  echo -e "${CYAN}Checking prerequisites...${RESET}"
  echo ""

  # Check Docker
  if command -v docker &> /dev/null; then
    docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo -e "  Docker: ${GREEN}${ICON_OK}${RESET} v$docker_version"
  else
    echo -e "  Docker: ${RED}${ICON_FAIL}${RESET} Not found"
    echo ""
    echo -e "${RED}Error: Docker is required but not installed.${RESET}"
    echo "Please install Docker from https://docker.com"
    exit 1
  fi

  # Check Docker Compose
  if docker compose version &> /dev/null; then
    compose_version=$(docker compose version --short 2>/dev/null || echo "unknown")
    echo -e "  Docker Compose: ${GREEN}${ICON_OK}${RESET} v$compose_version"
  else
    echo -e "  Docker Compose: ${RED}${ICON_FAIL}${RESET} Not found"
    echo ""
    echo -e "${RED}Error: Docker Compose is required.${RESET}"
    echo "Please ensure Docker Compose is installed."
    exit 1
  fi

  # Check Docker daemon
  if docker info &> /dev/null; then
    echo -e "  Docker Daemon: ${GREEN}${ICON_OK}${RESET} Running"
  else
    echo -e "  Docker Daemon: ${RED}${ICON_FAIL}${RESET} Not running"
    echo ""
    echo -e "${RED}Error: Docker daemon is not running.${RESET}"
    echo "Please start Docker and try again."
    exit 1
  fi

  # Check required files
  if [[ -f "$ENV_EXAMPLE" ]]; then
    echo -e "  .env.example: ${GREEN}${ICON_OK}${RESET} Found"
  else
    echo -e "  .env.example: ${RED}${ICON_FAIL}${RESET} Not found"
    echo ""
    echo -e "${RED}Error: backend/.env.example not found.${RESET}"
    exit 1
  fi

  if [[ -f "$INFRA_DIR/docker-compose.yml" ]]; then
    echo -e "  docker-compose.yml: ${GREEN}${ICON_OK}${RESET} Found"
  else
    echo -e "  docker-compose.yml: ${RED}${ICON_FAIL}${RESET} Not found"
    echo ""
    echo -e "${RED}Error: infra/docker-compose.yml not found.${RESET}"
    exit 1
  fi

  echo ""
}

# Generate secure key using Python
generate_key() {
  local key_type="$1"
  if [[ "$key_type" == "hex" ]]; then
    python3 -c "import secrets; print(secrets.token_hex(32))"
  else
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
  fi
}

# Setup environment file
setup_env() {
  echo -e "${CYAN}Configuring environment...${RESET}"
  echo ""

  if [[ -f "$ENV_FILE" ]]; then
    echo -e "  ${YELLOW}${ICON_WARN}${RESET} Existing .env file found."
    echo ""
    if confirm "  Overwrite with fresh configuration? (y/n)"; then
      cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d%H%M%S)"
      echo -e "  ${DIM}Backup created.${RESET}"
    else
      echo ""
      echo "  Keeping existing configuration."
      return 0
    fi
  fi

  # Copy template
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  echo -e "  ${GREEN}${ICON_OK}${RESET} Created .env from template"

  # Generate SECRET_KEY
  echo ""
  echo "  Generating secure keys..."
  local secret_key
  secret_key=$(generate_key "hex")
  sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$secret_key|" "$ENV_FILE"
  echo -e "  ${GREEN}${ICON_OK}${RESET} SECRET_KEY generated"

  # Generate PII_ENCRYPTION_KEY
  local pii_key
  pii_key=$(generate_key "urlsafe")
  sed -i.bak "s|^PII_ENCRYPTION_KEY=.*|PII_ENCRYPTION_KEY=$pii_key|" "$ENV_FILE"
  echo -e "  ${GREEN}${ICON_OK}${RESET} PII_ENCRYPTION_KEY generated"

  # Configure environment
  echo ""
  local flask_env
  flask_env=$(prompt "  Environment (development/production)" "development")
  sed -i.bak "s|^FLASK_ENV=.*|FLASK_ENV=$flask_env|" "$ENV_FILE"

  # Production warning
  if [[ "$flask_env" == "production" ]]; then
    echo ""
    echo -e "  ${YELLOW}+------------------------------------------+${RESET}"
    echo -e "  ${YELLOW}|  PRODUCTION MODE DETECTED                |${RESET}"
    echo -e "  ${YELLOW}|                                          |${RESET}"
    echo -e "  ${YELLOW}|  Ensure you:                             |${RESET}"
    echo -e "  ${YELLOW}|  - Use strong admin password             |${RESET}"
    echo -e "  ${YELLOW}|  - Configure CORS_ORIGINS properly       |${RESET}"
    echo -e "  ${YELLOW}|  - Set ALLOW_INSECURE_COOKIES=false      |${RESET}"
    echo -e "  ${YELLOW}|  - Back up PII_ENCRYPTION_KEY            |${RESET}"
    echo -e "  ${YELLOW}+------------------------------------------+${RESET}"
    echo ""

    if ! confirm "  Continue with production setup? (y/n)" "n"; then
      echo ""
      echo "  Setup cancelled."
      exit 0
    fi

    sed -i.bak "s|^ALLOW_INSECURE_COOKIES=.*|ALLOW_INSECURE_COOKIES=false|" "$ENV_FILE"
  fi

  # Configure admin credentials
  echo ""
  local admin_email
  admin_email=$(prompt "  Admin email" "admin@canvas-clay.local")
  sed -i.bak "s|^BOOTSTRAP_ADMIN_EMAIL=.*|BOOTSTRAP_ADMIN_EMAIL=$admin_email|" "$ENV_FILE"

  local admin_password
  if $NON_INTERACTIVE; then
    admin_password="CanvasClay$(date +%Y)!"
  else
    echo ""
    echo "  Admin password requirements:"
    echo "    - 8-128 characters"
    echo "    - At least one uppercase letter"
    echo "    - At least one lowercase letter"
    echo "    - At least one digit"
    echo ""
    read -sp "  Admin password: " admin_password
    echo ""
  fi
  sed -i.bak "s|^BOOTSTRAP_ADMIN_PASSWORD=.*|BOOTSTRAP_ADMIN_PASSWORD=$admin_password|" "$ENV_FILE"
  echo -e "  ${GREEN}${ICON_OK}${RESET} Admin credentials configured"

  # Clean up backup files from sed
  rm -f "${ENV_FILE}.bak"

  echo ""
  echo -e "  ${GREEN}${ICON_OK}${RESET} Environment configuration complete"
}

# Launch Docker containers
launch_containers() {
  echo ""
  echo -e "${CYAN}Starting Canvas & Clay...${RESET}"
  echo ""
  echo "  This may take a few minutes on first run."
  echo ""

  cd "$INFRA_DIR"

  # Build and start containers
  if docker compose up --build -d; then
    echo ""
    echo -e "  ${GREEN}${ICON_OK}${RESET} Containers started"
  else
    echo ""
    echo -e "  ${RED}${ICON_FAIL}${RESET} Failed to start containers"
    exit 1
  fi

  # Wait for backend to be ready
  echo ""
  echo "  Waiting for backend to be ready..."
  local max_attempts=30
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if curl -s http://localhost:5001/health > /dev/null 2>&1; then
      echo -e "  ${GREEN}${ICON_OK}${RESET} Backend is ready"
      break
    fi
    attempt=$((attempt + 1))
    sleep 2
    printf "."
  done

  if [[ $attempt -eq $max_attempts ]]; then
    echo ""
    echo -e "  ${YELLOW}${ICON_WARN}${RESET} Backend health check timed out"
    echo "  The services may still be starting. Check logs with:"
    echo "    docker compose -f infra/docker-compose.yml logs -f backend"
  fi
}

# Show completion message
show_completion() {
  echo ""
  echo -e "${BOLD}"
  echo "  +--------------------------------------------+"
  echo "  |                                            |"
  echo "  |  Setup Complete                            |"
  echo "  |                                            |"
  echo "  |  Canvas & Clay is now running.             |"
  echo "  |                                            |"
  echo "  |  Open your browser to:                     |"
  echo "  |  http://localhost:5173/setup               |"
  echo "  |                                            |"
  echo "  |  Login with your admin credentials to      |"
  echo "  |  complete the setup wizard.                |"
  echo "  |                                            |"
  echo "  |  Press Ctrl+C to stop the containers.      |"
  echo "  |                                            |"
  echo "  +--------------------------------------------+"
  echo -e "${RESET}"
  echo ""
  echo "  Useful commands:"
  echo ""
  echo "    View logs:"
  echo "      docker compose -f infra/docker-compose.yml logs -f"
  echo ""
  echo "    Stop containers:"
  echo "      docker compose -f infra/docker-compose.yml down"
  echo ""
  echo "    Restart after code changes:"
  echo "      docker compose -f infra/docker-compose.yml restart backend"
  echo ""
}

# Main execution
main() {
  show_banner
  check_prerequisites
  setup_env
  launch_containers
  show_completion

  # Follow logs if not non-interactive
  if ! $NON_INTERACTIVE; then
    echo ""
    if confirm "  View container logs? (y/n)" "y"; then
      cd "$INFRA_DIR"
      docker compose logs -f
    fi
  fi
}

# Run main
main
