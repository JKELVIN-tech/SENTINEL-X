#!/usr/bin/env bash
# Sentinel X — Setup Script v3
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✔${RESET}  $1"; }
info() { echo -e "${CYAN}  →${RESET}  $1"; }
warn() { echo -e "${YELLOW}  ⚠${RESET}  $1"; }
die()  { echo -e "${RED}  ✘  FATAL: $1${RESET}"; exit 1; }
hr()   { echo -e "${CYAN}  ────────────────────────────────────────${RESET}"; }

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     SENTINEL X v2.0 — SETUP SCRIPT       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

[[ $EUID -ne 0 ]] && die "Please run as root: sudo bash setup.sh"

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$WORK_DIR"
info "Working directory: $WORK_DIR"
hr

# ── Step 1: System packages
info "Installing system dependencies..."
apt-get update -qq 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  nmap postgresql postgresql-client nodejs npm curl git jq openssl 2>/dev/null || true
ok "System packages done"
hr

# ── Step 2: Node.js version
NODE_VER=$(node --version 2>/dev/null | grep -oP '\d+' | head -1 || echo "0")
if [[ "$NODE_VER" -lt 18 ]]; then
  info "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs >/dev/null 2>&1
fi
ok "Node.js $(node --version)"
hr

# ── Step 3: NMAP
NMAP_BIN=$(which nmap 2>/dev/null || echo "/usr/bin/nmap")
ok "NMAP: $($NMAP_BIN --version 2>/dev/null | head -1 || echo 'found')"
hr

# ── Step 4: .env file
if [[ ! -f ".env" ]]; then
  if [[ -f ".env.example" ]]; then
    cp .env.example .env
    ok ".env created from .env.example"
  else
    # Create .env from scratch
    info "Creating .env file..."
    RAND_API=$(openssl rand -hex 24)
    RAND_JWT=$(openssl rand -hex 32)
    cat > .env << ENVEOF
PORT=3000
HOST=127.0.0.1
NODE_ENV=development
API_KEY=${RAND_API}
JWT_SECRET=${RAND_JWT}
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL_DAYS=7
BCRYPT_ROUNDS=12
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=sentinelx
DB_USER=sentinelx
DB_PASSWORD=sentinelx
DB_SSL=false
DB_POOL_MAX=10
DB_IDLE_TIMEOUT=30000
DB_CONN_TIMEOUT=5000
NMAP_BINARY=${NMAP_BIN}
NMAP_OUTPUT_DIR=./reports/nmap
NMAP_MAX_CONCURRENT=3
NMAP_TIMEOUT_MS=300000
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=100
LOG_LEVEL=info
LOG_DIR=./logs
REPORTS_DIR=./reports
ANTHROPIC_API_KEY=
HASHCAT_BINARY=/usr/bin/hashcat
WORDLISTS_DIR=./wordlists
ENVEOF
    ok ".env created with fresh secrets"
  fi
else
  ok ".env already exists (keeping existing values)"
fi

# Replace CHANGE_ME placeholders if any remain
if grep -q "CHANGE_ME" .env 2>/dev/null; then
  RAND_API=$(openssl rand -hex 24)
  RAND_JWT=$(openssl rand -hex 32)
  sed -i "s|CHANGE_ME_run_openssl_rand_hex_24|${RAND_API}|g" .env
  sed -i "s|CHANGE_ME_run_openssl_rand_hex_32|${RAND_JWT}|g"  .env
  ok "Placeholder secrets replaced"
fi

# Update nmap path
sed -i "s|^NMAP_BINARY=.*|NMAP_BINARY=${NMAP_BIN}|g" .env
hr

# ── Step 5: npm install
info "Installing Node.js packages (this may take a minute)..."
npm install --silent 2>/dev/null || npm install
ok "npm packages ready"
hr

# ── Step 6: Directories
mkdir -p logs reports/nmap reports/hash wordlists public
ok "Directories created"
hr

# ── Step 7: PostgreSQL
info "Starting PostgreSQL..."
systemctl start postgresql 2>/dev/null || \
  service postgresql start 2>/dev/null || \
  true

sleep 2

# Fix pg_hba.conf to allow password auth from localhost
PG_HBA=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1 || echo "")
if [[ -n "$PG_HBA" ]]; then
  # Check if password/md5 auth is configured for local connections
  if ! grep -qE "^host.*sentinelx.*md5|^host.*all.*all.*127\.0\.0\.1.*md5|^host.*all.*all.*127\.0\.0\.1.*scram-sha-256" "$PG_HBA" 2>/dev/null; then
    info "Configuring pg_hba.conf for password authentication..."
    # Add password auth rule before any reject rules
    sed -i "s/^host.*all.*all.*127\.0\.0\.1\/32.*ident/host    all             all             127.0.0.1\/32            md5/" "$PG_HBA" || true
    # Also add explicit rule at the top of host entries
    sed -i "/^# IPv4 local connections:/a host    sentinelx       sentinelx       127.0.0.1\/32            md5" "$PG_HBA" 2>/dev/null || true
    systemctl reload postgresql 2>/dev/null || service postgresql reload 2>/dev/null || true
    ok "pg_hba.conf updated"
  fi
fi

# Create user + database
info "Configuring database..."
PG_USER_OK=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='sentinelx'" 2>/dev/null || echo "")
if [[ -z "$PG_USER_OK" ]]; then
  sudo -u postgres psql -c "CREATE USER sentinelx WITH PASSWORD 'sentinelx';" 2>/dev/null
  ok "Created DB user: sentinelx"
else
  ok "DB user 'sentinelx' already exists"
fi

PG_DB_OK=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='sentinelx'" 2>/dev/null || echo "")
if [[ -z "$PG_DB_OK" ]]; then
  sudo -u postgres psql -c "CREATE DATABASE sentinelx OWNER sentinelx;" 2>/dev/null
  ok "Created database: sentinelx"
else
  ok "Database 'sentinelx' already exists"
fi

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sentinelx TO sentinelx;" >/dev/null 2>&1 || true

# Test connection
sleep 1
if PGPASSWORD=sentinelx psql -h 127.0.0.1 -U sentinelx -d sentinelx -c "SELECT 1;" >/dev/null 2>&1; then
  ok "Database connection verified"
  DB_OK=true
else
  warn "Could not verify DB connection — check PostgreSQL is running and pg_hba.conf allows password auth"
  warn "Manual fix: sudo -u postgres psql -c \"ALTER USER sentinelx WITH PASSWORD 'sentinelx';\""
  DB_OK=false
fi
hr

# ── Step 8: Migrations
if [[ "$DB_OK" == "true" ]]; then
  info "Running database migrations..."
  if node src/db/migrate.js 2>&1; then
    ok "Migrations complete"
  else
    warn "Migrations failed — see output above"
  fi
else
  warn "Skipping migrations (no DB connection)"
  warn "After fixing PostgreSQL, run: node src/db/migrate.js"
fi
hr

# ── Step 9: systemd (optional)
read -rp $'\n  Install as systemd service? [y/N]: ' DO_SERVICE || true
if [[ "${DO_SERVICE:-N}" =~ ^[Yy]$ ]]; then
  NODE_BIN=$(which node)
  cat > /etc/systemd/system/sentinelx.service << EOF
[Unit]
Description=Sentinel X Penetration Testing Platform
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
ExecStart=${NODE_BIN} src/server.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelx
EnvironmentFile=${WORK_DIR}/.env

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable sentinelx
  ok "systemd service installed"
fi

# ── Summary
API_KEY_VAL=$(grep "^API_KEY=" .env | cut -d= -f2 2>/dev/null || echo "see .env")

echo ""
echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}   Sentinel X ready!${RESET}"
echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Start:         ${CYAN}npm start${RESET}"
echo -e "  Dashboard:     ${CYAN}http://127.0.0.1:3000${RESET}"
echo -e "  Default login: ${YELLOW}admin / SentinelX@admin${RESET}"
echo -e "  API Key:       ${YELLOW}${API_KEY_VAL}${RESET}"
echo ""
echo -e "  Troubleshoot:"
echo -e "    DB migration:   ${CYAN}node src/db/migrate.js${RESET}"
echo -e "    Health check:   ${CYAN}curl http://127.0.0.1:3000/health${RESET}"
echo -e "    Logs:           ${CYAN}tail -f logs/sentinel.log${RESET}"
echo ""
echo -e "  ${YELLOW}⚠  Change admin password on first login!${RESET}"
echo ""
