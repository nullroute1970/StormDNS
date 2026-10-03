#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/stormdns}"
DATA_DIR="${DATA_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-server_config.toml}"
KEY_FILE="${KEY_FILE:-encrypt_key.txt}"
BIN="${APP_DIR}/stormdns"
SAMPLE_URL="https://raw.githubusercontent.com/nullroute1970/StormDNS/refs/heads/main/server_config.toml.simple"

mkdir -p "${APP_DIR}" "${DATA_DIR}"

bootstrap_config() {
  local domain_value tmp_config

  domain_value="${DOMAIN:-}"
  if [[ -z "${domain_value}" ]]; then
    echo "ERROR: DOMAIN env is required when /data/${CONFIG_FILE} does not exist." >&2
    exit 1
  fi

  tmp_config="$(mktemp)"
  trap 'rm -f "${tmp_config}"' EXIT

  curl -fsSL --retry 3 --retry-delay 2 "${SAMPLE_URL}" -o "${tmp_config}"

  domain_value="${domain_value//&/\\&}"
  sed -E "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${domain_value}\"]|" "${tmp_config}" > "${DATA_DIR}/${CONFIG_FILE}"
  rm -f "${tmp_config}"
  trap - EXIT
}

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found or not executable: ${BIN}" >&2
  exit 1
fi

# If config doesn't exist in the data volume, create it.
if [[ ! -f "${DATA_DIR}/${CONFIG_FILE}" ]]; then
  bootstrap_config
fi

# Change to the data directory. The server will read its config from here
# and generate the encryption key here if it doesn't exist, ensuring
# both are persisted in the container volume.
cd "${DATA_DIR}"

exec "${BIN}" "$@"
