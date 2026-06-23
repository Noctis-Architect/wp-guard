#!/bin/bash
set -euo pipefail

# WP Scanner Installer Script
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUNICORN_PORT=5001

port_in_use() {
    ss -tln 2>/dev/null | grep -q ":${1} "
}

stop_existing_app() {
    if systemctl --user is-active wp-scanner &>/dev/null; then
        echo -e "${YELLOW}Stopping existing wp-scanner user service...${NC}"
        systemctl --user stop wp-scanner
    fi
    if systemctl is-active wp-scanner &>/dev/null; then
        echo -e "${YELLOW}Stopping existing wp-scanner system service...${NC}"
        sudo systemctl stop wp-scanner
    fi
    pkill -f "${PROJECT_DIR}/venv/bin/gunicorn.*app:app" 2>/dev/null || true
    sleep 1
}

echo -e "${GREEN}Starting WP Scanner Installation...${NC}"

if [[ "${EUID:-0}" -eq 0 ]]; then
    echo -e "${RED}Error: Do not run this script as root. It will use sudo only where needed.${NC}"
    exit 1
fi

# Check if OS is Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}Error: This script is only for Linux.${NC}"
    exit 1
fi

# Function to detect package manager
detect_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(detect_manager)

# Install Dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
if [ "$PKG_MANAGER" == "apt" ]; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv nginx curl sqlite3
elif [ "$PKG_MANAGER" == "yum" ]; then
    sudo yum update -y
    sudo yum install -y python3 python3-pip nginx curl sqlite
fi

# Set up Python Virtual Environment
echo -e "${GREEN}Setting up Python environment...${NC}"
cd "$PROJECT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    pip install flask requests gunicorn flask-sqlalchemy flask-socketio flask-cors eventlet
fi

# Web Server Configuration
echo -ne "${GREEN}Enter the port you want the app to run on (e.g. 8080): ${NC}"
read PORT

if [ -z "$PORT" ]; then
    PORT=8080
fi

if port_in_use "$GUNICORN_PORT"; then
    echo -e "${YELLOW}Internal port $GUNICORN_PORT is in use. Stopping existing WP Scanner processes...${NC}"
    stop_existing_app
fi

if port_in_use "$PORT"; then
    if pgrep -f "${PROJECT_DIR}.*gunicorn" >/dev/null; then
        echo -e "${YELLOW}Port $PORT is in use by an existing WP Scanner instance. Stopping it...${NC}"
        stop_existing_app
    fi
    if port_in_use "$PORT"; then
        echo -e "${RED}Error: Port $PORT is already in use by another process.${NC}"
        echo -e "Choose a different port (e.g. 8080) or stop the process using: ss -tlnp | grep :$PORT"
        exit 1
    fi
fi

# Create Database Directory
mkdir -p database

echo -e "${GREEN}Configuring Nginx on port $PORT...${NC}"

# Create Nginx Config
NGINX_CONF="/etc/nginx/sites-available/wp_scanner"
sudo bash -c "cat > $NGINX_CONF" <<EOF
server {
    listen $PORT;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:$GUNICORN_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
EOF

sudo ln -sf $NGINX_CONF /etc/nginx/sites-enabled/
sudo nginx -t
if ! sudo systemctl restart nginx; then
    echo -e "${RED}Error: nginx failed to start.${NC}"
    echo -e "Check logs with: sudo journalctl -xeu nginx.service"
    echo -e "Common cause: the chosen port is already in use."
    exit 1
fi

echo -e "${GREEN}Starting the application...${NC}"
# Use Gunicorn with eventlet worker for SocketIO support
nohup "${PROJECT_DIR}/venv/bin/gunicorn" \
    --worker-class eventlet \
    -w 1 \
    --bind "127.0.0.1:${GUNICORN_PORT}" \
    --timeout 120 \
    app:app > "${PROJECT_DIR}/app.log" 2>&1 &

sleep 1
if ! port_in_use "$GUNICORN_PORT"; then
    echo -e "${RED}Error: Gunicorn failed to start. See ${PROJECT_DIR}/app.log${NC}"
    exit 1
fi

echo -e "${GREEN}Installation complete!${NC}"
echo -e "You can access the app at: http://your-ip:$PORT"
