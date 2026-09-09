#!/usr/bin/env bash
set -Eeuo pipefail
# Serialize maintenance with watchdog; child backup inherits this lock.
if [[ "${AAS_MAINTENANCE_LOCKED:-}" != 1 ]]; then
  exec 9>/run/aas-vpn-watchdog.lock
  flock 9
  export AAS_MAINTENANCE_LOCKED=1
fi
(( EUID == 0 )) || { echo 'Run as root: sudo ./scripts/deploy.sh' >&2; exit 1; }
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${AAS_INSTALL_DIR:-/opt/aas-vpn}
cd "$source_dir"
if [[ "$source_dir" == "$target_dir" && -n "$(docker compose ps -q 2>/dev/null)" ]]; then
  echo 'Deploy an upgrade from a separate checkout so the backup retains the previous code and Compose files.' >&2
  exit 2
fi
if [[ ! -f .env && ! -f "$target_dir/.env" ]]; then
  cp .env.example .env
  echo 'Created .env. Configure server settings and run again.' >&2
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
for dependency in jq python3; do
  command -v "$dependency" >/dev/null || { apt-get update; apt-get install -y "$dependency"; }
done
# Preserve server-owned environment/config/data; snapshot before changing code or images.
if [[ -f "$target_dir/.env" && -f "$target_dir/compose.yml" ]]; then
  cd "$target_dir"
  AAS_BACKUP_ROOT="$target_dir" bash "$source_dir/scripts/backup.sh"
  cd "$source_dir"
fi
install -d -m 0755 "$target_dir"
if [[ "$source_dir" != "$target_dir" ]]; then
  for directory in portal router awg scripts systemd tests; do
    mkdir -p "$target_dir/$directory"
    cp -R "$source_dir/$directory/." "$target_dir/$directory/"
  done
  install -m 0644 compose.yml compose.edge.yml .env.example .dockerignore .gitignore .sonarcloud.properties AGENTS.md README.md "$target_dir/"
  [[ -f "$target_dir/.env" ]] || install -m 0600 .env "$target_dir/.env"
  mkdir -p "$target_dir/config/adguard"
  for file in Caddyfile sing-box.json adguard/AdGuardHome.yaml; do
    [[ -f "$target_dir/config/$file" ]] || install -m 0644 "config/$file" "$target_dir/config/$file"
  done
fi
cd "$target_dir"
# Leave rollback image pinning only after its image/data pair has been backed up.
python3 - <<'PYENV'
from pathlib import Path
path = Path('.env')
path.write_text(path.read_text().replace(':compose.rollback.json', ''))
PYENV
chmod 0600 .env
set -a
# shellcheck disable=SC1091
source .env
set +a
: "${VPN_DOMAIN:?Set VPN_DOMAIN}" "${PORTAL_DOMAIN:?Set PORTAL_DOMAIN}" "${COOKIE_DOMAIN:?Set COOKIE_DOMAIN}"
: "${VPN_SITE_ADDRESS:?Set VPN_SITE_ADDRESS}" "${PORTAL_SITE_ADDRESS:?Set PORTAL_SITE_ADDRESS}"
[[ "$VPN_DOMAIN" != *.example.com ]] || { echo 'Set real domains in .env' >&2; exit 2; }
docker compose config --quiet
if [[ "${AAS_USE_PREBUILT_IMAGES:-}" == 1 ]]; then
  while IFS= read -r image; do docker image inspect "$image" >/dev/null; done < <(docker compose config --images)
else
  docker compose build --pull
  docker compose pull --ignore-buildable
fi
for unit in systemd/*.service systemd/*.timer; do
  sed "s|/opt/aas-vpn|$target_dir|g" "$unit" > "/etc/systemd/system/$(basename "$unit")"
  chmod 0644 "/etc/systemd/system/$(basename "$unit")"
done
cat >/etc/sysctl.d/99-aas-vpn.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
vm.swappiness = 10
EOF
sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now docker
# Stop old AWG first; new AWG waits until the persistent host guard is ready.
docker compose stop awg2 sing-box
docker compose up -d --no-build --pull never --remove-orphans
systemctl enable --now aas-vpn.service aas-vpn-watchdog.timer
printf 'AAS VPN: https://%s · portal: https://%s/admin\n' "$VPN_DOMAIN" "$PORTAL_DOMAIN"
