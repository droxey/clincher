#!/usr/bin/env bash
# bootstrap.sh — Single-command OpenClaw deployment on Ubuntu 24.04
#
# Usage (as root on a fresh VPS):
#   curl -fsSL https://raw.githubusercontent.com/droxey/clincher/main/bootstrap.sh | bash
#
# Or inspect first:
#   curl -fsSL https://raw.githubusercontent.com/droxey/clincher/main/bootstrap.sh -o bootstrap.sh
#   less bootstrap.sh
#   bash bootstrap.sh
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────
REPO_URL="https://github.com/droxey/clincher.git"
INSTALL_DIR="/opt/clincher"
VAULT_PASS_FILE="${INSTALL_DIR}/.vault-pass"
LOG_FILE="/var/log/clincher-bootstrap.log"
REQUIRED_ID="ubuntu"
REQUIRED_VERSION="24.04"

# ── Colors (with no-color fallback) ────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null; then
  BOLD=$(tput bold)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  RED=$(tput setaf 1)
  CYAN=$(tput setaf 6)
  RESET=$(tput sgr0)
else
  BOLD="" GREEN="" YELLOW="" RED="" CYAN="" RESET=""
fi

# ── Helpers ────────────────────────────────────────────────────────────────
info()  { printf '%s==>%s %s\n' "$GREEN"  "$RESET" "$1"; }
warn()  { printf '%s==>%s %s\n' "$YELLOW" "$RESET" "$1"; }
err()   { printf '%s==> ERROR:%s %s\n' "$RED" "$RESET" "$1" >&2; }
header() { printf '\n%s%s── Phase %s ──%s\n\n' "$BOLD" "$CYAN" "$1" "$RESET"; }

mask_key() {
  local key="$1"
  if [[ ${#key} -gt 8 ]]; then
    printf '%s...%s' "${key:0:4}" "${key: -4}"
  else
    printf '****'
  fi
}

prompt_required() {
  local varname="$1" prompt_text="$2" validate="${3:-}"
  local value=""
  while true; do
    printf '%s: ' "$prompt_text"
    if [[ "$validate" == "silent" ]]; then
      read -rs value
      printf '\n'
      # Re-prompt with visible validation
      validate="${4:-}"
    else
      read -r value
    fi
    if [[ -z "$value" ]]; then
      warn "This field is required."
      continue
    fi
    if [[ -n "$validate" ]] && ! eval "$validate" <<< "$value" 2>/dev/null; then
      warn "Invalid input. Please try again."
      continue
    fi
    break
  done
  eval "$varname=\"\$value\""
}

prompt_default() {
  local varname="$1" prompt_text="$2" default="$3" validate="${4:-}"
  local value=""
  printf '%s [%s]: ' "$prompt_text" "$default"
  read -r value
  value="${value:-$default}"
  if [[ -n "$validate" ]] && ! eval "$validate" <<< "$value" 2>/dev/null; then
    warn "Invalid input — using default: $default"
    value="$default"
  fi
  eval "$varname=\"\$value\""
}

prompt_optional() {
  local varname="$1" prompt_text="$2"
  local value=""
  printf '%s (Enter to skip): ' "$prompt_text"
  read -rs value
  printf '\n'
  eval "$varname=\"\$value\""
}

cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    err "Bootstrap failed (exit code $exit_code)."
    if [[ -f "$LOG_FILE" ]]; then
      err "Check log: $LOG_FILE"
    fi
    err "Fix the issue and re-run — the script is idempotent."
  fi
  # Scrub any plaintext secret temp files
  rm -f /tmp/.clincher-vault-plain 2>/dev/null || true
}
trap cleanup EXIT

# ── Phase 1: Preflight ────────────────────────────────────────────────────
preflight() {
  header "1/6: Preflight checks"

  # Must be root
  if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
  fi

  # Must be Ubuntu 24.04
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" != "$REQUIRED_ID" || "${VERSION_ID:-}" != "$REQUIRED_VERSION" ]]; then
      err "Requires Ubuntu 24.04. Detected: ${PRETTY_NAME:-unknown}"
      exit 1
    fi
    info "OS: ${PRETTY_NAME}"
  else
    err "Cannot detect OS — /etc/os-release missing."
    exit 1
  fi

  # Internet connectivity
  if ! curl -fsSL --max-time 10 https://github.com -o /dev/null 2>/dev/null; then
    err "No internet connectivity. Cannot reach github.com."
    exit 1
  fi
  info "Internet connectivity OK"

  # Existing installation?
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    warn "Existing installation found at $INSTALL_DIR — will update."
    UPDATE_MODE=true
  else
    UPDATE_MODE=false
  fi
}

# ── Phase 2: Install Dependencies ─────────────────────────────────────────
install_deps() {
  header "2/6: Installing dependencies"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq

  info "Installing system packages..."
  apt-get install -y -qq \
    python3-pip python3-venv python3-full \
    pipx git curl openssl sshpass \
    > /dev/null 2>&1

  # Ansible via pipx
  if command -v ansible &>/dev/null; then
    info "Ansible already installed: $(ansible --version | head -1)"
  else
    info "Installing Ansible via pipx..."
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin \
      pipx install --include-deps ansible 2>&1 | tail -1
    if ! command -v ansible &>/dev/null; then
      warn "pipx install failed — falling back to apt..."
      apt-get install -y -qq ansible > /dev/null 2>&1
    fi
  fi

  # Verify
  if ! command -v ansible &>/dev/null; then
    err "Ansible installation failed."
    exit 1
  fi
  info "$(ansible --version | head -1)"
}

# ── Phase 3: Clone / Update Repo ──────────────────────────────────────────
clone_repo() {
  header "3/6: Setting up clincher repository"

  if [[ "$UPDATE_MODE" == "true" ]]; then
    info "Updating existing repository..."
    cd "$INSTALL_DIR"
    git pull --ff-only origin main 2>/dev/null || {
      warn "Fast-forward pull failed — stashing local changes and retrying..."
      git stash
      git pull --ff-only origin main
    }
  else
    info "Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
  fi

  info "Installing Ansible Galaxy collections..."
  ansible-galaxy collection install -r requirements.yml --force -p ./collections 2>&1 | tail -3
  info "Repository ready at $INSTALL_DIR"
}

# ── Phase 4: Interactive Configuration ─────────────────────────────────────
interactive() {
  header "4/6: Configuration"
  printf '%sEnter your deployment settings below.%s\n' "$BOLD" "$RESET"
  printf 'API keys are entered silently (no echo).\n\n'

  # ── Required: Anthropic API key ──
  local anthropic_key=""
  while true; do
    printf 'Anthropic API key: '
    read -rs anthropic_key
    printf '\n'
    if [[ -z "$anthropic_key" ]]; then
      warn "Required."
      continue
    fi
    if [[ "$anthropic_key" != sk-ant-* ]]; then
      warn "Must start with 'sk-ant-'."
      continue
    fi
    break
  done
  ANTHROPIC_API_KEY="$anthropic_key"

  # ── Required: Voyage API key ──
  local voyage_key=""
  while true; do
    printf 'Voyage API key: '
    read -rs voyage_key
    printf '\n'
    if [[ -z "$voyage_key" ]]; then
      warn "Required."
      continue
    fi
    if [[ "$voyage_key" != pa-* ]]; then
      warn "Must start with 'pa-'."
      continue
    fi
    break
  done
  VOYAGE_API_KEY="$voyage_key"

  # ── Required: Domain ──
  local domain=""
  while true; do
    printf 'Domain name (e.g., openclaw.example.com): '
    read -r domain
    if [[ -z "$domain" || "$domain" != *.* ]]; then
      warn "Enter a valid domain name."
      continue
    fi
    break
  done
  DOMAIN="$domain"

  # ── Admin IP (auto-detect) ──
  local detected_ip=""
  detected_ip=$(curl -fsSL --max-time 10 https://ifconfig.me 2>/dev/null || echo "")
  prompt_default ADMIN_IP "Admin IP for SSH/firewall whitelist" "${detected_ip:-0.0.0.0}"

  # ── Reverse proxy ──
  prompt_default REVERSE_PROXY "Reverse proxy (caddy/tunnel/tailscale)" "caddy"
  case "$REVERSE_PROXY" in
    caddy|tunnel|tailscale) ;;
    *) warn "Invalid choice — defaulting to caddy."; REVERSE_PROXY="caddy" ;;
  esac

  # ── Tunnel token (only if tunnel selected) ──
  TUNNEL_TOKEN=""
  if [[ "$REVERSE_PROXY" == "tunnel" ]]; then
    while true; do
      printf 'Cloudflare Tunnel token: '
      read -rs TUNNEL_TOKEN
      printf '\n'
      if [[ -z "$TUNNEL_TOKEN" ]]; then
        warn "Required when using Cloudflare Tunnel."
        continue
      fi
      break
    done
  fi

  # ── Optional: Telegram bot token ──
  printf 'Telegram bot token (Enter to skip): '
  read -rs TELEGRAM_BOT_TOKEN
  printf '\n'
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
  if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
    TELEGRAM_ENABLED=true
  else
    TELEGRAM_ENABLED=false
  fi

  # ── SSH port ──
  prompt_default SSH_PORT "SSH port" "9922"

  # ── Confirmation ──
  printf '\n%s── Configuration Summary ────────────────────────%s\n' "$BOLD" "$RESET"
  printf '  Anthropic key:  %s\n' "$(mask_key "$ANTHROPIC_API_KEY")"
  printf '  Voyage key:     %s\n' "$(mask_key "$VOYAGE_API_KEY")"
  printf '  Domain:         %s\n' "$DOMAIN"
  printf '  Admin IP:       %s\n' "$ADMIN_IP"
  printf '  Reverse proxy:  %s\n' "$REVERSE_PROXY"
  printf '  Telegram:       %s\n' "$( [[ "$TELEGRAM_ENABLED" == "true" ]] && echo "enabled" || echo "disabled" )"
  printf '  SSH port:       %s\n' "$SSH_PORT"
  printf '%s─────────────────────────────────────────────────%s\n\n' "$BOLD" "$RESET"

  local confirm=""
  printf 'Proceed? [Y/n] '
  read -r confirm
  if [[ "${confirm,,}" == "n" ]]; then
    info "Aborted. Re-run bootstrap.sh to try again."
    exit 0
  fi
}

# ── Phase 5: Generate Configuration ────────────────────────────────────────
generate_config() {
  header "5/6: Generating configuration"

  cd "$INSTALL_DIR"

  # ── Check for existing vault ──
  if [[ -f "group_vars/all/vault.yml" ]]; then
    local overwrite=""
    printf 'Existing vault.yml found. Overwrite? [y/N] '
    read -r overwrite
    if [[ "${overwrite,,}" != "y" ]]; then
      info "Keeping existing vault.yml. Skipping secret generation."
      SKIP_VAULT=true
    else
      SKIP_VAULT=false
    fi
  else
    SKIP_VAULT=false
  fi

  if [[ "$SKIP_VAULT" == "false" ]]; then
    # ── Generate internal secrets ──
    info "Generating internal secrets..."
    LITELLM_MASTER_KEY=$(openssl rand -hex 32)
    GATEWAY_TOKEN=$(openssl rand -hex 32)
    BACKUP_ENCRYPTION_KEY=$(openssl rand -hex 32)

    # ── Vault password ──
    if [[ -f "$VAULT_PASS_FILE" ]]; then
      info "Reusing existing vault password."
    else
      info "Generating vault password..."
      openssl rand -base64 32 > "$VAULT_PASS_FILE"
      chmod 0600 "$VAULT_PASS_FILE"
    fi

    # ── Write vault.yml ──
    info "Writing vault.yml..."
    cat > "group_vars/all/vault.yml" <<VAULT
---
anthropic_api_key: "${ANTHROPIC_API_KEY}"
voyage_api_key: "${VOYAGE_API_KEY}"
litellm_master_key: "${LITELLM_MASTER_KEY}"
gateway_token: "${GATEWAY_TOKEN}"
backup_encryption_key: "${BACKUP_ENCRYPTION_KEY}"
telegram_bot_token: "${TELEGRAM_BOT_TOKEN:-}"
tunnel_token: "${TUNNEL_TOKEN:-}"
github_token: ""
VAULT

    # ── Encrypt vault ──
    info "Encrypting vault.yml..."
    ansible-vault encrypt "group_vars/all/vault.yml" \
      --vault-password-file "$VAULT_PASS_FILE"
  fi

  # ── Write inventory for local execution ──
  info "Configuring inventory for local execution..."
  cat > "inventory/hosts.yml" <<'INVENTORY'
---
all:
  hosts:
    openclaw:
      ansible_host: 127.0.0.1
      ansible_connection: local
      ansible_user: root
      ansible_become: false
INVENTORY

  # ── Write bootstrap overrides (preserves vars.yml for clean git pulls) ──
  info "Writing bootstrap overrides..."
  cat > "group_vars/all/zzz_bootstrap.yml" <<OVERRIDES
---
# Auto-generated by bootstrap.sh — do not edit manually.
# This file overrides vars.yml defaults for this deployment.
admin_ip: "${ADMIN_IP}"
domain: "${DOMAIN}"
ssh_port: ${SSH_PORT}
reverse_proxy: "${REVERSE_PROXY}"
telegram_enabled: ${TELEGRAM_ENABLED}
OVERRIDES

  # ── Update .gitignore ──
  for entry in ".vault-pass" "group_vars/all/zzz_bootstrap.yml"; do
    if ! grep -qxF "$entry" .gitignore 2>/dev/null; then
      echo "$entry" >> .gitignore
    fi
  done

  info "Configuration complete."
}

# ── Phase 6: Run the Playbook ──────────────────────────────────────────────
run_playbook() {
  header "6/6: Deploying OpenClaw"

  cd "$INSTALL_DIR"

  info "Running Ansible playbook (this will take a while)..."
  info "Log: $LOG_FILE"
  printf '\n'

  ansible-playbook playbook.yml \
    --vault-password-file "$VAULT_PASS_FILE" \
    --skip-tags bootstrap \
    2>&1 | tee "$LOG_FILE"

  local exit_code=${PIPESTATUS[0]}
  if [[ $exit_code -ne 0 ]]; then
    err "Playbook failed with exit code $exit_code."
    err "Review the log: $LOG_FILE"
    exit "$exit_code"
  fi

  printf '\n'
  printf '%s════════════════════════════════════════════════════%s\n' "$BOLD" "$RESET"
  printf '%s  OpenClaw deployed successfully!%s\n' "$GREEN" "$RESET"
  printf '\n'
  printf '  Dashboard:    https://%s\n' "$DOMAIN"
  printf '  Vault pass:   %s\n' "$VAULT_PASS_FILE"
  printf '  Log:          %s\n' "$LOG_FILE"
  printf '  Re-deploy:    cd %s && make deploy\n' "$INSTALL_DIR"
  printf '\n'
  printf '  %sNext steps:%s\n' "$BOLD" "$RESET"
  printf '  1. Ensure DNS points %s to this server\n' "$DOMAIN"
  printf '  2. Test: curl -I https://%s\n' "$DOMAIN"
  printf '  3. Back up %s to a secure location\n' "$VAULT_PASS_FILE"
  printf '%s════════════════════════════════════════════════════%s\n' "$BOLD" "$RESET"
}

# ── Main ───────────────────────────────────────────────────────────────────
main() {
  printf '\n%s%s  OpenClaw Bootstrap — clincher%s\n' "$BOLD" "$CYAN" "$RESET"
  printf '  https://github.com/droxey/clincher\n\n'

  preflight
  install_deps
  clone_repo
  interactive
  generate_config
  run_playbook
}

main "$@"
