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
# Build before stopping the live stack. Backup records actual running image IDs.
server_env="$source_dir/.env"
[[ ! -f "$target_dir/.env" ]] || server_env="$target_dir/.env"
if [[ "${AAS_USE_PREBUILT_IMAGES:-}" != 1 ]]; then
  docker compose --env-file "$server_env" -f compose.yml build --pull
fi
migration_required=0
backup_result=$(mktemp)
backup_dir=
reference_path=$(mktemp)
restore_on_error() {
  local code=$?
  trap - ERR
  if [[ -n "$backup_dir" && -f "$backup_dir/COMPLETE" ]]; then
    echo 'Deployment failed; restoring the saved image/data pair.' >&2
    bash "$target_dir/scripts/rollback.sh" "$backup_dir"
  elif [[ -f "$target_dir/compose.yml" ]]; then
    (cd "$target_dir" && docker compose up -d --pull never --no-build)
  fi
  exit "$code"
}
trap restore_on_error ERR
if [[ -f "$target_dir/.env" && -f "$target_dir/compose.yml" ]]; then
  cd "$target_dir"
  if docker compose config --services | grep -qx auth-sync; then
    migration_required=1
    docker compose stop caddy
    docker exec -i aas-portal python - < "$source_dir/scripts/export_legacy.py"
    docker cp aas-portal:/tmp/native-reference.json "$reference_path"
  fi
  AAS_BACKUP_ROOT="$target_dir" AAS_BACKUP_KEEP_STOPPED=1 AAS_BACKUP_RESULT_FILE="$backup_result" bash "$source_dir/scripts/backup.sh"
  read -r backup_dir < "$backup_result"
  if [[ "$migration_required" == 1 ]]; then install -m 0600 "$reference_path" "$backup_dir/client-configs.json"; fi
  cd "$source_dir"
fi
rm -f "$backup_result" "$reference_path"
install -d -m 0755 "$target_dir"
if [[ "$source_dir" != "$target_dir" ]]; then
  for directory in portal router awg scripts systemd tests examples; do
    mkdir -p "$target_dir/$directory"
    cp -R "$source_dir/$directory/." "$target_dir/$directory/"
  done
  rm -f "$target_dir/portal/session.mjs" "$target_dir/portal/sync.py" "$target_dir/portal/package.json" "$target_dir/portal/package-lock.json" "$target_dir/awg/start.sh" "$target_dir/awg/prepare.mjs" "$target_dir/tests/test_sync.py"
  install -m 0644 compose.yml compose.edge.yml .env.example .dockerignore .gitignore .sonarcloud.properties AGENTS.md DESIGN.md README.md "$target_dir/"
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
python3 scripts/native_proxy.py config/Caddyfile
set -a
# shellcheck disable=SC1091
source .env
set +a
: "${VPN_DOMAIN:?Set VPN_DOMAIN}" "${PORTAL_DOMAIN:?Set PORTAL_DOMAIN}" "${COOKIE_DOMAIN:?Set COOKIE_DOMAIN}"
: "${VPN_SITE_ADDRESS:?Set VPN_SITE_ADDRESS}" "${PORTAL_SITE_ADDRESS:?Set PORTAL_SITE_ADDRESS}"
[[ "$VPN_DOMAIN" != *.example.com ]] || { echo 'Set real domains in .env' >&2; exit 2; }
docker compose config --quiet
while IFS= read -r image; do docker image inspect "$image" >/dev/null; done < <(docker compose config --images)
docker compose run --rm --no-deps storage-init
if [[ "$migration_required" == 1 ]]; then
  docker compose --profile migration run --rm --no-deps -v "$backup_dir/client-configs.json:/reference.json:ro" migrate-native python migrate_native.py --reference /reference.json
  docker compose --profile migration run --rm --no-deps -v "$backup_dir/client-configs.json:/reference.json:ro" migrate-native python migrate_native.py --reference /reference.json --apply
  docker compose run --rm --no-deps storage-init
elif ! docker compose run --rm --no-deps --entrypoint python awg2 bootstrap.py --check; then
  docker compose run --rm --no-deps --entrypoint python awg2 bootstrap.py --endpoint "$VPN_DOMAIN" --public-port "${AWG_PORT:-443}"
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
docker compose run --rm --no-deps --entrypoint python portal -c "from pathlib import Path; Path('/data/maintenance').touch()"
# Stop old AWG first; new AWG waits until the persistent host guard is ready.
docker compose stop awg2 sing-box
docker compose up -d --no-build --pull never --remove-orphans
# Wait for the native controller and router before re-enabling automatic recovery.
for _attempt in $(seq 1 60); do
  if docker inspect --format '{{.State.Health.Status}}' awg2 | grep -qx healthy &&
     docker inspect --format '{{.State.Health.Status}}' sing-box | grep -qx healthy; then break; fi
  sleep 2
done
docker inspect --format '{{.State.Health.Status}}' awg2 | grep -qx healthy
docker inspect --format '{{.State.Health.Status}}' sing-box | grep -qx healthy
if [[ "${AAS_KEEP_MAINTENANCE:-0}" != 1 ]]; then
  docker compose exec -T portal python -c "from pathlib import Path; Path('/data/maintenance').unlink(missing_ok=True)"
fi
systemctl enable --now aas-vpn.service aas-vpn-watchdog.timer
trap - ERR
printf 'AAS VPN: https://%s · portal: https://%s/admin\n' "$VPN_DOMAIN" "$PORTAL_DOMAIN"
