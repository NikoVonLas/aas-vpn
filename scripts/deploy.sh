#!/usr/bin/env bash
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo "Run as root: sudo ./scripts/deploy.sh" >&2
  exit 1
fi

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root_dir"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env. Set VPN_DOMAIN and run this script again." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1091
source .env
set +a
: "${VPN_DOMAIN:?Set VPN_DOMAIN in .env}"
: "${PORTAL_DOMAIN:?Set PORTAL_DOMAIN in .env}"
: "${PORTAL_SESSION_SECRET:?Set PORTAL_SESSION_SECRET in .env}"
: "${COOKIE_DOMAIN:?Set COOKIE_DOMAIN in .env}"
if [[ "$VPN_DOMAIN" == "vpn.example.com" ]]; then
  echo "Replace vpn.example.com in .env first." >&2
  exit 2
fi

if ! command -v docker >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin
fi
docker compose version >/dev/null

install -d -m 0755 /opt/aas-vpn
install -d -m 0755 /opt/aas-vpn/config /opt/aas-vpn/config/adguard /opt/aas-vpn/scripts
install -d -m 0755 /opt/aas-vpn/portal
install -m 0644 compose.yml .env /opt/aas-vpn/
install -m 0644 config/Caddyfile config/sing-box.json /opt/aas-vpn/config/
install -m 0644 config/adguard/AdGuardHome.yaml /opt/aas-vpn/config/adguard/
install -m 0644 portal/Dockerfile portal/requirements.txt portal/app.py portal/sync.py /opt/aas-vpn/portal/
install -m 0755 scripts/watchdog.sh /opt/aas-vpn/scripts/
install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/

cat >/etc/sysctl.d/99-aas-vpn.conf <<'EOF'
net.ipv4.ip_forward = 1
vm.swappiness = 10
EOF
sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now docker aas-vpn.service aas-vpn-watchdog.timer
docker compose -f /opt/aas-vpn/compose.yml --env-file /opt/aas-vpn/.env \
  up -d --pull always --remove-orphans
systemctl restart aas-vpn-watchdog.timer

echo "AAS VPN is running: https://${VPN_DOMAIN}"
echo "Client portal: https://${PORTAL_DOMAIN} (admin: /admin)"
echo "Complete the wg-easy wizard and use 10.42.42.44 as the client DNS server."
echo "For AdGuard setup, open an SSH tunnel: ssh -L 3000:127.0.0.1:3000 <server>"
