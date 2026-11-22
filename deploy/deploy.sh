#!/usr/bin/env bash
#
# addadollar.com - deploy / configure script for a Debian or Ubuntu VPS (root access).
#
# What it does, in order:
#   1. Checks your .env (Stripe keys, moderation key, public URL).
#   2. Checks that DNS for the domain points at this server (read-only, never changes DNS).
#   3. Installs Node.js and a reverse proxy (Caddy by default, or nginx + certbot).
#   4. Copies the app to the target folder, installs dependencies, runs it as a service.
#   5. Connects the domain to the app, forces HTTPS (301) and gets a Let's Encrypt certificate.
#   6. Checks that http:// redirects to https:// and that the app answers.
#
# What it never does: it never edits DNS and never touches mail (MX, SPF, DKIM, Zimbra).
# It's safe to run again: re-running just updates the app and restarts it.
#
# Usage (from the unzipped project folder, on the server):
#   sudo bash deploy/deploy.sh --email you@example.com
#   sudo bash deploy/deploy.sh --proxy nginx --email you@example.com
#   bash deploy/deploy.sh --dry-run            # prints what it would do, changes nothing

set -euo pipefail

DOMAIN="addadollar.com"
APP_DIR="/var/www/addadollar"
APP_USER="addadollar"
PROXY="caddy"
EMAIL=""
DRY_RUN=0
SKIP_DNS=0
FIREWALL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
  cat <<'EOF'
Options:
  --domain NAME       Domain to serve (default: addadollar.com)
  --app-dir PATH      Where the app is installed (default: /var/www/addadollar)
  --proxy caddy|nginx Reverse proxy (default: caddy, which handles Let's Encrypt by itself)
  --email ADDRESS     E-mail for Let's Encrypt expiry notices (recommended)
  --skip-dns-check    Don't stop if DNS doesn't point at this server yet (nginx mode)
  --firewall          Also open ports 80/443 and your SSH port with ufw, then enable ufw
  --dry-run           Print the steps without changing anything
  -h, --help          Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain)         DOMAIN="${2:?missing value for --domain}"; shift 2 ;;
    --app-dir)        APP_DIR="${2:?missing value for --app-dir}"; shift 2 ;;
    --proxy)          PROXY="${2:?missing value for --proxy}"; shift 2 ;;
    --email)          EMAIL="${2:?missing value for --email}"; shift 2 ;;
    --skip-dns-check) SKIP_DNS=1; shift ;;
    --firewall)       FIREWALL=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Runs a command, or just prints it in --dry-run mode.
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}

# Same, for a shell snippet that needs pipes or redirects.
run_sh() {
  # pipefail: a failed download in "curl ... | bash" must stop the script, not pass silently.
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$1"; else bash -o pipefail -c "$1"; fi
}

# Writes stdin to a file with a given mode (or announces it in --dry-run mode).
write_file() {
  local path="$1" mode="${2:-644}"
  if [ "$DRY_RUN" = 1 ]; then
    printf '[dry-run] would write %s (mode %s)\n' "$path" "$mode"
    cat >/dev/null
  else
    cat >"$path"
    chmod "$mode" "$path"
  fi
}

# Reads a value from the project's .env. Values are never printed.
get_env() {
  local key="$1"
  { grep -E "^${key}=" "$SRC_DIR/.env" 2>/dev/null || true; } | tail -n1 | cut -d= -f2- | tr -d '\r'
}

# Fills a deploy template (written for addadollar.com / port 3000 / /var/www/addadollar).
render() {
  local file="$1"
  local out
  out="$(sed \
    -e "s#/var/www/addadollar#${APP_DIR}#g" \
    -e "s#127\.0\.0\.1:3000#127.0.0.1:${PORT}#g" \
    -e "s#addadollar\.com#${DOMAIN}#g" \
    "$file")"
  if [ -n "$EMAIL" ]; then
    out="$(printf '%s\n' "$out" | sed "s#__EMAIL__#${EMAIL}#g")"
  else
    out="$(printf '%s\n' "$out" | sed '/__EMAIL__/d')"
  fi
  printf '%s\n' "$out"
}

# ---------------------------------------------------------------
# 1. Pre-flight checks
# ---------------------------------------------------------------
preflight() {
  say "Pre-flight checks"

  [ "$DRY_RUN" = 1 ] || [ "$(id -u)" -eq 0 ] || die "Run this script as root (sudo bash deploy/deploy.sh)."
  [ "$DRY_RUN" = 1 ] || command -v apt-get >/dev/null 2>&1 || die "This script supports Debian/Ubuntu (apt-get) only."
  [ -f "$SRC_DIR/server.js" ] || die "server.js not found in $SRC_DIR. Run the script from the project folder."
  [ -f "$SRC_DIR/.env" ] || die "No .env file in $SRC_DIR. Copy .env.example to .env and fill it in first."

  case "$PROXY" in caddy|nginx) ;; *) die "--proxy must be 'caddy' or 'nginx'." ;; esac
  printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$' || die "Invalid domain: $DOMAIN"

  PORT="$(get_env PORT)"; PORT="${PORT:-3000}"
  printf '%s' "$PORT" | grep -Eq '^[0-9]{2,5}$' || die "PORT in .env must be a number."

  local mode node_env
  mode="$(get_env PAYMENT_MODE)"
  node_env="$(get_env NODE_ENV)"
  [ "$node_env" = "production" ] || warn "NODE_ENV is not 'production' in .env: HTTPS redirect, HSTS and strict checks will be off."

  if [ "$mode" = "stripe" ]; then
    local key missing=""
    for key in STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET OPENAI_API_KEY; do
      [ -n "$(get_env "$key")" ] || missing="$missing $key"
    done
    [ -z "$missing" ] || die "These .env values are empty:$missing"
  else
    warn "PAYMENT_MODE is '$mode' (not 'stripe'). Visitors would NOT be able to pay for real."
  fi

  local base_host
  base_host="$(get_env BASE_URL | sed -E 's#^https?://##; s#[/:].*$##')"
  [ "$base_host" = "$DOMAIN" ] || warn "BASE_URL in .env points at '$base_host', not '$DOMAIN'. Stripe return links would be wrong."

  echo "Domain: $DOMAIN | App folder: $APP_DIR | Proxy: $PROXY | App port: $PORT | Payments: $mode"
}

# ---------------------------------------------------------------
# 2. DNS check (read-only)
# ---------------------------------------------------------------
dns_check() {
  say "Checking DNS (read-only, nothing is changed)"

  local server_ip dns_ip www_ip aaaa
  server_ip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  dns_ip="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)"
  www_ip="$(getent ahostsv4 "www.$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)"
  aaaa="$(getent ahostsv6 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)"

  echo "This server's public IP : ${server_ip:-unknown}"
  echo "$DOMAIN resolves to     : ${dns_ip:-nothing yet}"
  echo "www.$DOMAIN resolves to : ${www_ip:-nothing yet}"

  local ok=1
  if [ -z "$server_ip" ]; then
    warn "Couldn't detect this server's public IP, so DNS can't be compared."
  else
    [ "$dns_ip" = "$server_ip" ] || { ok=0; warn "$DOMAIN does not point at this server yet."; }
    [ "$www_ip" = "$server_ip" ] || { ok=0; warn "www.$DOMAIN does not point at this server yet."; }
  fi
  [ -z "$aaaa" ] || warn "$DOMAIN has an IPv6 (AAAA) record ($aaaa). Make sure it's this server's IPv6, or remove it."

  if [ "$ok" = 0 ]; then
    cat <<EOF

In your DNS zone, change ONLY these records (leave everything else as it is):
    A    @     ->  ${server_ip:-<this server's IP>}
    A    www   ->  ${server_ip:-<this server's IP>}
Do NOT touch MX, TXT (SPF/DKIM/DMARC), autodiscover/autoconfig CNAMEs or any mail host:
that's your Zimbra mail setup.
EOF
    if [ "$PROXY" = "nginx" ] && [ "$SKIP_DNS" = 0 ] && [ "$DRY_RUN" = 0 ]; then
      die "certbot needs DNS to point here first. Fix DNS and run again, or use --skip-dns-check."
    fi
    [ "$PROXY" != "caddy" ] || echo "Caddy will keep retrying the certificate until DNS is right, so we carry on."
  fi
}

# ---------------------------------------------------------------
# 3. Packages
# ---------------------------------------------------------------
install_packages() {
  say "Installing packages"
  run apt-get update -y
  run apt-get install -y curl ca-certificates gnupg rsync

  local node_major=0
  if command -v node >/dev/null 2>&1; then
    node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  fi
  if [ "$node_major" -lt 20 ]; then
    echo "Installing Node.js 22 from NodeSource (the app needs Node 20 or newer)."
    run_sh "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -"
    run apt-get install -y nodejs
  else
    echo "Node.js $node_major is already installed."
  fi

  if [ "$PROXY" = "caddy" ]; then
    if ! command -v caddy >/dev/null 2>&1; then
      echo "Installing Caddy from the official repository."
      run apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
      run_sh "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"
      run_sh "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list"
      run apt-get update -y
      run apt-get install -y caddy
    else
      echo "Caddy is already installed."
    fi
  else
    run apt-get install -y nginx certbot
  fi
}

# ---------------------------------------------------------------
# 4. The app itself
# ---------------------------------------------------------------
deploy_app() {
  say "Installing the app into $APP_DIR"

  id -u "$APP_USER" >/dev/null 2>&1 || run useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
  run mkdir -p "$APP_DIR"

  # Your database ("data") and node_modules are never overwritten or deleted.
  run rsync -a --delete --exclude node_modules --exclude data --exclude .git --exclude '*.zip' "$SRC_DIR"/ "$APP_DIR"/
  run mkdir -p "$APP_DIR/data"
  run chown -R "$APP_USER:$APP_USER" "$APP_DIR"
  run chmod 600 "$APP_DIR/.env"
  run chmod 700 "$APP_DIR/data"

  run bash -c "cd '$APP_DIR' && runuser -u '$APP_USER' -- env HOME='$APP_DIR' npm ci --omit=dev --no-audit --no-fund"

  render "$SCRIPT_DIR/addadollar.service" | write_file /etc/systemd/system/addadollar.service 644
  run systemctl daemon-reload
  run systemctl enable addadollar
  run systemctl restart addadollar

  if [ "$DRY_RUN" = 0 ]; then
    local i
    for i in $(seq 1 20); do
      if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
        echo "The app is up on port $PORT."
        return
      fi
      sleep 1
    done
    journalctl -u addadollar -n 30 --no-pager || true
    die "The app did not start. See the log above (and: journalctl -u addadollar)."
  fi
}

# ---------------------------------------------------------------
# 5a. Caddy: domain, HTTPS redirect, automatic Let's Encrypt
# ---------------------------------------------------------------
configure_caddy() {
  say "Connecting $DOMAIN to the app with Caddy"

  run mkdir -p /etc/caddy/conf.d
  render "$SCRIPT_DIR/Caddyfile" | write_file /etc/caddy/conf.d/addadollar.caddy 644

  # Make sure the main Caddyfile loads our file, without removing anything that's already there.
  if [ "$DRY_RUN" = 1 ]; then
    echo "[dry-run] would append 'import /etc/caddy/conf.d/*.caddy' to /etc/caddy/Caddyfile if missing"
  else
    touch /etc/caddy/Caddyfile
    if ! grep -qF 'import /etc/caddy/conf.d/*.caddy' /etc/caddy/Caddyfile; then
      cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
      printf '\nimport /etc/caddy/conf.d/*.caddy\n' >> /etc/caddy/Caddyfile
    fi
  fi

  run caddy validate --config /etc/caddy/Caddyfile
  run systemctl enable caddy
  run systemctl reload-or-restart caddy
  echo "Caddy requests and renews the Let's Encrypt certificate by itself."
}

# ---------------------------------------------------------------
# 5b. nginx + certbot
# ---------------------------------------------------------------
configure_nginx() {
  say "Connecting $DOMAIN to the app with nginx + certbot"

  run mkdir -p /var/www/certbot

  # Step 1: plain-HTTP site, just enough to pass the Let's Encrypt challenge.
  write_file /etc/nginx/sites-available/addadollar.conf 644 <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 200 'ok'; add_header Content-Type text/plain; }
}
EOF
  run ln -sf /etc/nginx/sites-available/addadollar.conf /etc/nginx/sites-enabled/addadollar.conf
  run nginx -t
  run systemctl enable nginx
  run systemctl reload-or-restart nginx

  # Step 2: get the certificate (it renews itself with the certbot timer, then reloads nginx).
  local email_args
  if [ -n "$EMAIL" ]; then email_args="-m $EMAIL"; else email_args="--register-unsafely-without-email"; fi
  run_sh "certbot certonly --webroot -w /var/www/certbot -d '$DOMAIN' -d 'www.$DOMAIN' $email_args --agree-tos --non-interactive --deploy-hook 'systemctl reload nginx'"

  # Step 3: the real site: 301 to https, HSTS, reverse proxy to the app.
  render "$SCRIPT_DIR/nginx.conf" | write_file /etc/nginx/sites-available/addadollar.conf 644
  run nginx -t
  run systemctl reload nginx
}

# ---------------------------------------------------------------
# 5c. Firewall (opt-in)
# ---------------------------------------------------------------
configure_firewall() {
  [ "$FIREWALL" = 1 ] || return 0
  say "Firewall (ufw)"
  run apt-get install -y ufw
  local ssh_port
  ssh_port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
  ssh_port="${ssh_port:-22}"
  run ufw allow "${ssh_port}/tcp"
  run ufw allow 80/tcp
  run ufw allow 443/tcp
  run ufw --force enable
}

# ---------------------------------------------------------------
# 6. Verification
# ---------------------------------------------------------------
verify() {
  say "Verifying"
  if [ "$DRY_RUN" = 1 ]; then
    echo "[dry-run] would check that http://$DOMAIN/ answers 301 -> https and that https works"
    return
  fi

  sleep 3
  local http_result
  http_result="$(curl -sS -o /dev/null --max-time 10 -w '%{http_code} %{redirect_url}' --resolve "${DOMAIN}:80:127.0.0.1" "http://${DOMAIN}/" 2>&1 || true)"
  echo "http://$DOMAIN/  ->  $http_result"
  case "$http_result" in
    "301 https://"*) echo "OK: HTTP is redirected to HTTPS with a 301." ;;
    *) warn "Expected '301 https://...'. Check the proxy configuration." ;;
  esac

  local https_result
  https_result="$(curl -sS -I --max-time 15 --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/healthz" 2>&1 | head -n 12 || true)"
  if printf '%s' "$https_result" | grep -q '^HTTP/.* 200'; then
    echo "OK: https://$DOMAIN/ answers."
    printf '%s' "$https_result" | grep -i '^strict-transport-security' || warn "No HSTS header seen (it is only sent when NODE_ENV=production)."
  else
    warn "https://$DOMAIN/ isn't answering yet. If DNS was just changed, the certificate can take a minute or two."
    echo "  Look at: journalctl -u ${PROXY} -n 50 --no-pager"
  fi
}

summary() {
  cat <<EOF

================================================================
 Done. Remaining manual steps:

 1. DNS: only the A records for "@" and "www" point at this server.
    Leave MX, SPF/DKIM/DMARC (TXT) and mail CNAMEs exactly as they are (Zimbra).
 2. Stripe Dashboard > Developers > Webhooks: endpoint
        https://${DOMAIN}/api/stripe/webhook
    events: checkout.session.completed, checkout.session.async_payment_succeeded,
            checkout.session.expired
    and the signing secret must be the STRIPE_WEBHOOK_SECRET value in .env.
 3. Make one real \$1 payment yourself, check the block appears, then refund it in Stripe.
 4. Money report any time:  cd ${APP_DIR} && sudo -u ${APP_USER} npm run report
 5. Logs:  journalctl -u addadollar -f
================================================================
EOF
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
[ "$DRY_RUN" = 0 ] || say "DRY RUN: nothing will be changed"

preflight
dns_check
install_packages
deploy_app
if [ "$PROXY" = "caddy" ]; then configure_caddy; else configure_nginx; fi
configure_firewall
verify
summary
