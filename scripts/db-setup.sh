#!/usr/bin/env bash
# ============================================================
#  Sentinel X — Database Setup Script
#  Run this if the main setup.sh DB step failed, or to
#  reset the database to a clean state.
#
#  Usage:
#    sudo bash scripts/db-setup.sh
#    sudo bash scripts/db-setup.sh --reset   (drops and recreates)
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✔${RESET}  $1"; }
info() { echo -e "${CYAN}  →${RESET}  $1"; }
warn() { echo -e "${YELLOW}  ⚠${RESET}  $1"; }
die()  { echo -e "${RED}  ✘  $1${RESET}"; exit 1; }

RESET_DB=false
[[ "${1:-}" == "--reset" ]] && RESET_DB=true

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash scripts/db-setup.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${CYAN}  Sentinel X — Database Setup${RESET}"
echo ""

# ── Load .env
if [[ -f ".env" ]]; then
  set -a
  source .env
  set +a
  ok ".env loaded"
else
  die ".env not found. Run setup.sh first, or create .env from .env.example"
fi

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-sentinelx}"
DB_USER="${DB_USER:-sentinelx}"
DB_PASS="${DB_PASSWORD:-sentinelx}"

# ── Start PostgreSQL
info "Starting PostgreSQL service..."
systemctl start postgresql 2>/dev/null || \
  service postgresql start 2>/dev/null || \
  pg_ctlcluster "$(pg_lsclusters -h 2>/dev/null | awk '{print $1}' | head -1)" main start 2>/dev/null || \
  warn "Could not start PostgreSQL automatically — assuming it is already running"

sleep 2

# ── Check PostgreSQL is running
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" >/dev/null 2>&1; then
  die "PostgreSQL is not reachable at ${DB_HOST}:${DB_PORT}. Start it with: sudo systemctl start postgresql"
fi
ok "PostgreSQL is running"

# ── Fix pg_hba.conf
PG_HBA=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1 || echo "")
if [[ -n "$PG_HBA" ]]; then
  info "Checking pg_hba.conf: $PG_HBA"
  if ! grep -qE "sentinelx.*md5|127\.0\.0\.1.*md5|127\.0\.0\.1.*scram" "$PG_HBA" 2>/dev/null; then
    info "Adding md5 auth rule to pg_hba.conf..."
    # Backup
    cp "$PG_HBA" "${PG_HBA}.bak.$(date +%s)"
    # Add rule after the IPv4 comment line
    sed -i "/^# IPv4 local connections:/a host    sentinelx       sentinelx       127.0.0.1\/32            md5" "$PG_HBA" 2>/dev/null || true
    # Also add for all if not present
    if ! grep -q "127.0.0.1/32.*md5\|127.0.0.1/32.*scram" "$PG_HBA"; then
      echo "host    all             all             127.0.0.1/32            md5" >> "$PG_HBA"
    fi
    systemctl reload postgresql 2>/dev/null || service postgresql reload 2>/dev/null || true
    sleep 1
    ok "pg_hba.conf updated"
  else
    ok "pg_hba.conf already has password auth"
  fi
fi

# ── Reset if requested
if $RESET_DB; then
  warn "Dropping database ${DB_NAME}..."
  sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME};" 2>/dev/null || true
  sudo -u postgres psql -c "DROP USER IF EXISTS ${DB_USER};" 2>/dev/null || true
  ok "Existing database dropped"
fi

# ── Create user
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
  sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" 2>/dev/null
  ok "Created user: ${DB_USER}"
else
  # Ensure password matches .env
  sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null 2>&1 || true
  ok "User '${DB_USER}' exists — password synced"
fi

# ── Create database
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" 2>/dev/null
  ok "Created database: ${DB_NAME}"
else
  ok "Database '${DB_NAME}' already exists"
fi

# ── Grants
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" >/dev/null 2>&1 || true
ok "Privileges granted"

# ── Test connection
sleep 1
if PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT current_user, current_database();" >/dev/null 2>&1; then
  ok "Connection test passed: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
else
  die "Connection test FAILED.
  Try running manually:
    PGPASSWORD=${DB_PASS} psql -h ${DB_HOST} -U ${DB_USER} -d ${DB_NAME}
  Check pg_hba.conf and PostgreSQL logs: journalctl -u postgresql -n 50"
fi

# ── Run migrations
info "Running migrations..."
if node src/db/migrate.js; then
  ok "All migrations applied"
else
  die "Migration failed — see output above"
fi

echo ""
echo -e "${GREEN}  Database setup complete!${RESET}"
echo ""
echo -e "  Connection: ${CYAN}${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}${RESET}"
echo -e "  Start app:  ${CYAN}npm start${RESET}"
echo ""
