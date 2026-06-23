#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="wp-scanner"
USER_UNIT_DIR="${HOME}/.config/systemd/user"
SERVICE_FILE="${USER_UNIT_DIR}/${SERVICE_NAME}.service"
PORT="${WP_SCANNER_PORT:-5000}"
SYSTEM_MODE=false

usage() {
    echo "Usage: $0 [--system]"
    echo "  (default)  Install as user service (no sudo)"
    echo "  --system   Install as system service (requires sudo)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --system) SYSTEM_MODE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
    esac
done

echo -e "${GREEN}Installing ${SERVICE_NAME} systemd service...${NC}"

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}Error: systemd is only available on Linux.${NC}"
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    echo -e "${RED}Error: systemctl not found. Is systemd installed?${NC}"
    exit 1
fi

if [[ ! -x "${PROJECT_DIR}/venv/bin/gunicorn" ]]; then
    echo -e "${YELLOW}Virtual environment missing or incomplete. Setting up...${NC}"
    python3 -m venv "${PROJECT_DIR}/venv"
    "${PROJECT_DIR}/venv/bin/pip" install --upgrade pip
    "${PROJECT_DIR}/venv/bin/pip" install -r "${PROJECT_DIR}/requirements.txt"
fi

mkdir -p "${PROJECT_DIR}/database"

if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
    SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    cat > "${PROJECT_DIR}/.env" <<EOF
# WP Scanner environment (used by systemd)
WP_SCANNER_SECRET=${SECRET}
WP_SCANNER_PORT=${PORT}
EOF
    chmod 600 "${PROJECT_DIR}/.env"
    echo -e "${GREEN}Created ${PROJECT_DIR}/.env with a random secret key.${NC}"
fi

if $SYSTEM_MODE; then
    TARGET="/etc/systemd/system/${SERVICE_NAME}.service"
    TEMPLATE="${PROJECT_DIR}/deploy/wp-scanner.service"
    sed \
        -e "s|/home/mr-noctis/projects/wp_scanner|${PROJECT_DIR}|g" \
        -e "s|^User=.*|User=$(id -un)|" \
        -e "s|^Group=.*|Group=$(id -gn)|" \
        -e "s|^Environment=WP_SCANNER_PORT=.*|Environment=WP_SCANNER_PORT=${PORT}|" \
        "${TEMPLATE}" | sudo tee "${TARGET}" >/dev/null

    sudo systemctl daemon-reload
    sudo systemctl enable "${SERVICE_NAME}"
    sudo systemctl restart "${SERVICE_NAME}"

    echo
    echo -e "${GREEN}System service installed and started.${NC}"
    echo -e "  Status:  sudo systemctl status ${SERVICE_NAME}"
    echo -e "  Logs:    sudo journalctl -u ${SERVICE_NAME} -f"
    sudo systemctl --no-pager status "${SERVICE_NAME}"
else
    mkdir -p "${USER_UNIT_DIR}"
    sed \
        -e "s|/home/mr-noctis/projects/wp_scanner|${PROJECT_DIR}|g" \
        -e "s|^Environment=WP_SCANNER_PORT=.*|Environment=WP_SCANNER_PORT=${PORT}|" \
        "${PROJECT_DIR}/deploy/wp-scanner.user.service" > "${SERVICE_FILE}"

    systemctl --user daemon-reload
    systemctl --user enable "${SERVICE_NAME}"
    systemctl --user restart "${SERVICE_NAME}"

    if loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q 'Linger=no'; then
        echo
        echo -e "${YELLOW}Note: service stops when you log out unless lingering is enabled:${NC}"
        echo -e "  loginctl enable-linger $(id -un)"
    fi

    echo
    echo -e "${GREEN}User service installed and started.${NC}"
    echo -e "  Status:  systemctl --user status ${SERVICE_NAME}"
    echo -e "  Logs:    journalctl --user -u ${SERVICE_NAME} -f"
    echo -e "  Stop:    systemctl --user stop ${SERVICE_NAME}"
    echo -e "  URL:     http://127.0.0.1:${PORT}/"
    echo
    systemctl --user --no-pager status "${SERVICE_NAME}"
fi
