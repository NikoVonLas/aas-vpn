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
server_env="$source_dir/.env"
[[ ! -f "$target_dir/.env" ]] || server_env="$target_dir/.env"
migration_required=0
backup_result=$(mktemp)
backup_dir=
reference_path=$(mktemp)
declare -a image_pins=()
declare -a image_references=()
declare -a build_services=()

source_changed() {
  local relative=$1
  [[ -e "$target_dir/$relative" ]] || return 0
  ! diff -qr "$target_dir/$relative" "$source_dir/$relative" >/dev/null
}

plan_build() {
  if [[ ! -f "$target_dir/compose.yml" ]]; then
    build_services=(portal awg2 awg-controller sing-box)
    return
  fi
  if source_changed portal || source_changed awg/model.py; then build_services+=(portal); fi
  if source_changed awg/Dockerfile || source_changed awg/dataplane.sh; then
    build_services+=(awg2 awg-controller)
  elif source_changed awg; then
    build_services+=(awg-controller)
  fi
  if source_changed router || source_changed portal/routing.py; then build_services+=(sing-box); fi
}

pin_running_images() {
  local container image reference pin index=0
  [[ -f "$target_dir/.env" && -f "$target_dir/compose.yml" ]] || return
  while IFS= read -r container; do
    [[ -n "$container" ]] || continue
    image=$(docker inspect --format '{{.Image}}' "$container")
    reference=$(docker inspect --format '{{.Config.Image}}' "$container")
    pin="aas-vpn-deploy-pin:${BASHPID}-${index}"
    docker image tag "$image" "$pin"
    image_pins+=("$pin")
    image_references+=("$reference")
    ((index += 1))
  done < <(cd "$target_dir" && docker compose ps -q)
}

restore_image_tags() {
  local index
  for index in "${!image_pins[@]}"; do
    docker image tag "${image_pins[$index]}" "${image_references[$index]}"
  done
}

cleanup_image_pins() {
  local pin
  for pin in "${image_pins[@]}"; do
    docker image rm "$pin" >/dev/null 2>&1 || true
  done
}

restore_on_error() {
  local code=$?
  trap - ERR
  if [[ -n "$backup_dir" && -f "$backup_dir/COMPLETE" ]]; then
    echo 'Deployment failed; restoring the saved image/data pair.' >&2
    bash "$target_dir/scripts/rollback.sh" "$backup_dir"
  elif [[ -f "$target_dir/compose.yml" ]]; then
    restore_image_tags
    (cd "$target_dir" && docker compose up -d --pull never --no-build)
  fi
  exit "$code"
}
trap restore_on_error ERR
trap cleanup_image_pins EXIT
pin_running_images
plan_build
# Build only changed data planes. Pins keep the actual running image IDs
# addressable while Compose replaces their ordinary tags.
if [[ "${AAS_USE_PREBUILT_IMAGES:-}" != 1 ]]; then
  if (( ${#build_services[@]} )); then
    printf 'Building changed services: %s\n' "${build_services[*]}"
    docker compose --env-file "$server_env" -f compose.yml build --pull "${build_services[@]}"
  else
    echo 'No application image changes detected.'
  fi
fi
if [[ -f "$target_dir/.env" && -f "$target_dir/compose.yml" ]]; then
  cd "$target_dir"
  if docker compose config --services | grep -qx auth-sync; then
    migration_required=1
    docker compose stop caddy
    python3 "$source_dir/scripts/check_legacy_peers.py"
    docker exec -i aas-portal python - < "$source_dir/scripts/export_legacy.py"
    docker cp aas-portal:/data/native-reference.json "$reference_path"
    docker exec aas-portal python -c "from pathlib import Path; Path('/data/native-reference.json').unlink()"
  fi
  AAS_BACKUP_ROOT="$target_dir" AAS_BACKUP_MODE=online AAS_BACKUP_KEEP_MAINTENANCE=1 \
    AAS_BACKUP_RESULT_FILE="$backup_result" bash "$source_dir/scripts/backup.sh"
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
  # Remove retired application assets without touching deployment-owned files.
  for obsolete in portal/static/js/intlTelInputWithUtils.min.js portal/static/js/admin-auth.js portal/static/css/intlTelInput.min.css portal/.dockerignore; do
    rm -f "$target_dir/$obsolete"
  done
  rm -f "$target_dir/portal/session.mjs" "$target_dir/portal/sync.py" "$target_dir/portal/package.json" "$target_dir/portal/package-lock.json" "$target_dir/awg/start.sh" "$target_dir/awg/prepare.mjs" "$target_dir/tests/test_sync.py"
  install -m 0644 compose.yml .env.example .dockerignore .gitignore .sonarcloud.properties AGENTS.md DESIGN.md README.md "$target_dir/"
  [[ -f "$target_dir/.env" ]] || install -m 0600 .env "$target_dir/.env"
  if [[ -f compose.local.yml && ! -e "$target_dir/compose.local.yml" ]]; then
    install -m 0600 compose.local.yml "$target_dir/compose.local.yml"
  fi
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
python3 scripts/native_proxy.py
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
  docker compose --profile migration run --rm --no-deps -v "$backup_dir/client-configs.json:/reference.json:ro" migrate-native python migrate_native.py --reference
  docker compose --profile migration run --rm --no-deps -v "$backup_dir/client-configs.json:/reference.json:ro" migrate-native python migrate_native.py --reference --apply
  docker compose run --rm --no-deps storage-init
elif ! docker compose --profile tools run --rm --no-deps awg-bootstrap bootstrap.py --check; then
  docker compose --profile tools run --rm --no-deps awg-bootstrap bootstrap.py --endpoint "$VPN_DOMAIN" --public-port "${AWG_PORT:-443}" \
    --network "${VPN_CLIENT_CIDR:-10.19.0.0/24}" --dns "${AWG_CLIENT_DNS:-10.42.42.44}"
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
# The portal has a fixed Compose address, so a second `compose run portal`
# cannot join the production network while the live portal still owns it.
docker compose run --rm --no-deps --entrypoint python storage-init -c "from pathlib import Path; Path('/data/maintenance').touch()"
# Compose recreates only services whose image or runtime configuration changed.
docker compose up -d --no-build --pull never --remove-orphans
# Wait for the native controller and router before re-enabling automatic recovery.
health_format='{{.State.Health.Status}}'
for _attempt in $(seq 1 60); do
  if docker inspect --format "$health_format" awg2 | grep -qx healthy &&
     docker inspect --format "$health_format" awg-controller | grep -qx healthy &&
     docker inspect --format "$health_format" sing-box | grep -qx healthy &&
     docker exec sing-box python -c "import json; s=json.load(open('/routing-status/status.json')); assert s['running'] and s['state']=='applied'"; then break; fi
  sleep 2
done
docker inspect --format "$health_format" awg2 | grep -qx healthy
docker inspect --format "$health_format" awg-controller | grep -qx healthy
docker inspect --format "$health_format" sing-box | grep -qx healthy
docker exec sing-box python -c "import json; s=json.load(open('/routing-status/status.json')); assert s['running'] and s['state']=='applied'"
if [[ "${AAS_KEEP_MAINTENANCE:-0}" != 1 ]]; then
  docker compose exec -T portal python -c "from pathlib import Path; Path('/data/maintenance').unlink(missing_ok=True)"
fi
systemctl enable --now aas-vpn.service aas-vpn-watchdog.timer
trap - ERR
printf 'AAS VPN: https://%s · portal: https://%s/admin\n' "$VPN_DOMAIN" "$PORTAL_DOMAIN"
