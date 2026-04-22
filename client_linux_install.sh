#!/usr/bin/env bash
#
# StormDNS Client Linux Installer
#
# Run this script from the directory where the release archive was extracted.
# It installs the StormDNS client as a systemd service so it starts on boot.
# No internet access is required; all files are taken from the current directory.
#
# Usage:
#   sudo bash client_linux_install.sh

set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || log_error "Missing command: $1"; }
extract_config_version() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  grep '^CONFIG_VERSION' "$f" | awk -F'=' '{print $2}' | tr -d ' "' | head -n1 || true
}
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

if [[ "${EUID}" -ne 0 ]]; then
  log_error "Run this script as root (sudo)."
fi

INSTALL_DIR="$(pwd -P)"
[[ -n "${PWD:-}" ]] && INSTALL_DIR="$PWD"
if [[ "$INSTALL_DIR" == /dev/fd* || "$INSTALL_DIR" == /proc/*/fd* ]]; then
  INSTALL_DIR="$(pwd -P)"
fi
log_info "Installation directory: $INSTALL_DIR"
cd "$INSTALL_DIR" || log_error "Cannot access install directory: $INSTALL_DIR"

echo -e "${MAGENTA}${BOLD}"
echo "  __  __           _             _____  _   _  _____ "
echo " |  \/  |         | |           |  __ \| \ | |/ ____|"
echo " | \  / | __ _ ___| |_ ___ _ __ | |  | |  \| | (___  "
echo " | |\/| |/ _\` / __| __/ _ \ '__|| |  | | . \ |\___ \ "
echo " | |  | | (_| \__ \ ||  __/ |   | |__| | |\  |____) |"
echo " |_|  |_|\__,_|___/\__\___|_|   |_____/|_| \_|_____/ "
echo -e "          StormDNS Client Auto-Installer${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"

require_cmd systemctl

stop_existing_stormdns_client_service() {
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^stormdns-client\.service'; then
    log_info "Stopping existing StormDNS client service..."
    systemctl stop stormdns-client 2>/dev/null || true

    for _ in 1 2 3 4 5; do
      if ! systemctl is-active --quiet stormdns-client; then
        break
      fi
      sleep 1
    done

    local main_pid
    main_pid="$(systemctl show stormdns-client --property MainPID --value 2>/dev/null || true)"
    if [[ -n "${main_pid:-}" && "$main_pid" != "0" ]] && kill -0 "$main_pid" 2>/dev/null; then
      log_warn "stormdns-client service is still active. Sending SIGTERM to MainPID: $main_pid"
      kill "$main_pid" 2>/dev/null || true
      sleep 2
      kill -0 "$main_pid" 2>/dev/null && kill -9 "$main_pid" 2>/dev/null || true
    fi

    systemctl reset-failed stormdns-client 2>/dev/null || true
  fi
}

log_header "Stopping Existing StormDNS Client"
stop_existing_stormdns_client_service

log_header "Locating Client Binary"
# The installer is bundled inside the release archive alongside the binary.
# Find the most recently modified StormDNS_Client_* file in the current directory.
shopt -s nullglob
client_bins=(StormDNS_Client_*)
shopt -u nullglob
[[ ${#client_bins[@]} -eq 0 ]] && log_error "No StormDNS_Client_* binary found in $INSTALL_DIR. Run this script from the extracted release directory."
EXECUTABLE="${client_bins[0]}"
log_info "Found binary: $EXECUTABLE"
chmod +x "$EXECUTABLE"
log_success "Binary is ready."

log_header "Configuration"
[[ -f "client_config.toml" ]] || log_error "client_config.toml not found in $INSTALL_DIR."
CURRENT_VERSION="$(extract_config_version client_config.toml)"
if [[ -z "${CURRENT_VERSION:-}" ]]; then
  log_error "client_config.toml is invalid (CONFIG_VERSION missing)."
fi
if [[ -f "client_config.toml.backup" ]]; then
  BACKUP_VERSION="$(extract_config_version client_config.toml.backup)"
  if [[ -z "${BACKUP_VERSION:-}" ]]; then
    log_error "Backup config is too old (CONFIG_VERSION missing). Merge manually."
  fi

  if [[ "$BACKUP_VERSION" == "$CURRENT_VERSION" ]]; then
    mv -f client_config.toml.backup client_config.toml
    log_info "Config restored from backup."
  elif version_lt "$BACKUP_VERSION" "$CURRENT_VERSION"; then
    OLD_CFG_NAME="client_config_$(date +%Y%m%d_%H%M%S).toml"
    mv -f client_config.toml.backup "$OLD_CFG_NAME"
    log_warn "Old config version detected (backup=$BACKUP_VERSION < new=$CURRENT_VERSION)."
    log_warn "Previous config renamed to: $OLD_CFG_NAME"
    log_info "Using fresh config template; please set DOMAINS and other required fields."
  else
    log_error "Backup config version is newer than the bundled config (backup=$BACKUP_VERSION, new=$CURRENT_VERSION). Merge manually."
  fi
fi

# When running as a systemd service the process is non-interactive,
# so switch the startup mode from the default "ask" to "logs" to avoid
# waiting indefinitely for user input on every restart.
if grep -q '^STARTUP_MODE[[:space:]]*=[[:space:]]*"ask"' client_config.toml; then
  sed -i 's/^STARTUP_MODE[[:space:]]*=.*$/STARTUP_MODE = "logs"/' client_config.toml
  log_info "STARTUP_MODE set to \"logs\" for non-interactive service operation."
fi

log_header "Installing System Service"
SVC="/etc/systemd/system/stormdns-client.service"
cat > "$SVC" <<EOF
[Unit]
Description=StormDNS Client
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$EXECUTABLE --config $INSTALL_DIR/client_config.toml
Restart=always
RestartSec=5
User=root

LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
TimeoutStopSec=15
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable stormdns-client >/dev/null 2>&1 || log_warn "Could not enable stormdns-client service at boot."
systemctl restart stormdns-client

sleep 2
if ! systemctl is-active --quiet stormdns-client; then
  journalctl -u stormdns-client -n 50 --no-pager || true
  log_error "Service failed to start. See logs above."
fi

log_success "StormDNS client service is running."

echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${YELLOW}>${NC} Start:   systemctl start stormdns-client"
echo -e "  ${YELLOW}>${NC} Stop:    systemctl stop stormdns-client"
echo -e "  ${YELLOW}>${NC} Restart: systemctl restart stormdns-client"
echo -e "  ${YELLOW}>${NC} Logs:    journalctl -u stormdns-client -f"
echo -e "\n${BOLD}Files:${NC}"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/client_config.toml"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/client_resolvers.txt"
echo -e "${YELLOW}Note:${NC} Edit client_config.toml (set DOMAINS, ENCRYPTION_KEY, etc.) then run:"
echo -e "  ${YELLOW}>${NC} systemctl restart stormdns-client"
