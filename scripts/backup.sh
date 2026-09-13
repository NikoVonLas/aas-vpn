#!/usr/bin/env bash
# Consistent image + volume backup. Online mode pauses one writer at a time so
# the WireGuard network namespace remains alive throughout the snapshot.
set -Eeuo pipefail
# Serialize maintenance with watchdog; child backup inherits this lock.
if [[ "${AAS_MAINTENANCE_LOCKED:-}" != 1 ]]; then
  exec 9>/run/aas-vpn-watchdog.lock
  flock 9
  export AAS_MAINTENANCE_LOCKED=1
fi
cd "${AAS_BACKUP_ROOT:-$(dirname "${BASH_SOURCE[0]}")/..}"
umask 077
backup_dir="$(pwd)/backups/$(date -u +%Y%m%dT%H%M%SZ)"
backup_mode=${AAS_BACKUP_MODE:-stopped}
[[ "$backup_mode" == stopped || "$backup_mode" == online ]] || { echo 'AAS_BACKUP_MODE must be stopped or online' >&2; exit 2; }
if [[ "$backup_mode" == online && "${AAS_BACKUP_KEEP_STOPPED:-0}" == 1 ]]; then
  echo 'AAS_BACKUP_KEEP_STOPPED is incompatible with online mode' >&2
  exit 2
fi
mkdir -p "$backup_dir"
docker compose config --format json > "$backup_dir/compose-resolved.json"
printf '%s\n' "$backup_mode" > "$backup_dir/mode"
docker image inspect alpine:3.22 >/dev/null 2>&1 || docker pull alpine:3.22
python3 - "$backup_dir" <<'PY'
import json, pathlib, subprocess, sys
path = pathlib.Path(sys.argv[1])
config = json.loads((path / 'compose-resolved.json').read_text())
services, images = {}, set()
for service in config['services']:
    ids = subprocess.check_output(['docker', 'compose', 'ps', '-aq', service], text=True).split()
    if ids:
        image = subprocess.check_output(['docker', 'inspect', '-f', '{{.Image}}', ids[0]], text=True).strip()
        services[service] = {'image': image, 'pull_policy': 'never'}
        images.add(image)
(path / 'images.json').write_text(json.dumps({'services': services}))
if images:
    subprocess.run(['docker', 'image', 'save', '-o', str(path / 'images.tar'), *sorted(images)], check=True)
PY
declare -a paused_containers=()
declare -A archived_volumes=()
declare -A available_volumes=()
maintenance_container=
maintenance_created=0
backup_container=

unpause_all() {
  local container index
  for ((index=${#paused_containers[@]}-1; index>=0; index--)); do
    container=${paused_containers[$index]}
    docker unpause "$container" >/dev/null 2>&1 || true
  done
  paused_containers=()
}

clear_maintenance() {
  [[ "$maintenance_created" == 1 && -n "$maintenance_container" ]] || return
  docker exec "$maintenance_container" sh -c 'rm -f /data/maintenance' >/dev/null 2>&1 || true
}

stop_archiver() {
  [[ -n "$backup_container" ]] || return
  docker kill "$backup_container" >/dev/null 2>&1 || true
  backup_container=
}

# Restart or unpause on failure; a migration can retain a successful stopped snapshot.
finish_backup() {
  local backup_status=$?
  unpause_all
  stop_archiver
  if [[ "$backup_status" != 0 || "${AAS_BACKUP_KEEP_MAINTENANCE:-0}" != 1 ]]; then
    clear_maintenance
  fi
  if [[ "$backup_mode" == stopped && ( "$backup_status" != 0 || "${AAS_BACKUP_KEEP_STOPPED:-0}" != 1 ) ]]; then
    docker compose up -d --pull never >/dev/null
  fi
}
trap finish_backup EXIT

archive_volumes() {
  local key
  local -a keys=()
  for key in "$@"; do
    [[ -z "${archived_volumes[$key]:-}" ]] || continue
    [[ -n "${available_volumes[$key]:-}" ]] || continue
    keys+=("$key")
  done
  (( ${#keys[@]} )) || return 0
  # shellcheck disable=SC2016 # $key belongs to the Alpine shell below.
  docker exec "$backup_container" sh -c '
    for key do
      cd "/volumes/$key"
      tar --exclude="./maintenance" -czf "/backup/volume-$key.tar.gz" .
    done
  ' sh "${keys[@]}"
  for key in "${keys[@]}"; do archived_volumes[$key]=1; done
}

start_archiver() {
  local key volume
  local -a docker_args=(run -d --rm --network none -v "$backup_dir:/backup")
  while IFS= read -r key; do
    volume=$(jq -r --arg key "$key" '.volumes[$key].name // empty' "$backup_dir/compose-resolved.json")
    [[ -n "$volume" ]] || continue
    docker volume inspect "$volume" >/dev/null 2>&1 || continue
    available_volumes[$key]=1
    docker_args+=(-v "$volume:/volumes/$key:ro")
  done < <(jq -r '.volumes | keys[]' "$backup_dir/compose-resolved.json")
  docker_args+=(alpine:3.22 sleep 300)
  backup_container=$(docker "${docker_args[@]}")
}

snapshot_service() {
  local service=$1 container state paused_at pause_ms
  shift
  container=$(docker compose ps -q "$service")
  if [[ -n "$container" ]]; then
    state=$(docker inspect --format '{{.State.Running}} {{.State.Paused}}' "$container")
    if [[ "$state" == 'true false' ]]; then
      docker pause "$container" >/dev/null
      paused_containers+=("$container")
      paused_at=$(date +%s%N)
    else
      container=
    fi
  fi
  archive_volumes "$@"
  if [[ -n "$container" ]]; then
    docker unpause "$container" >/dev/null
    unset 'paused_containers[-1]'
    pause_ms=$(( ($(date +%s%N) - paused_at) / 1000000 ))
    printf 'Snapshot pause: %s %dms\n' "$service" "$pause_ms"
  fi
}

tar --exclude='./backups' --exclude='./.git' -czf "$backup_dir/project.tar.gz" .
start_archiver
if [[ "$backup_mode" == online ]]; then
  maintenance_container=$(docker compose ps -q portal)
  if [[ -n "$maintenance_container" ]] && ! docker exec "$maintenance_container" test -e /data/maintenance; then
    docker exec "$maintenance_container" sh -c 'touch /data/maintenance'
    maintenance_created=1
  fi
  snapshot_service portal portal_data auth_data ru_configs
  awg_controller=$(docker compose ps -q awg-controller 2>/dev/null || true)
  if [[ -n "$awg_controller" ]]; then
    snapshot_service awg-controller awg_data awg_control awg_network
  else
    # Back up releases from before the stable data-plane split safely as well.
    snapshot_service awg2 awg_data awg_control awg_network
  fi
  snapshot_service sing-box router_state routing_status
  snapshot_service adguard-home adguard_work
  snapshot_service caddy caddy_data caddy_config
  mapfile -t remaining_volumes < <(jq -r '.volumes | keys[]' "$backup_dir/compose-resolved.json")
  archive_volumes "${remaining_volumes[@]}"
else
  docker compose stop
  mapfile -t remaining_volumes < <(jq -r '.volumes | keys[]' "$backup_dir/compose-resolved.json")
  archive_volumes "${remaining_volumes[@]}"
fi
touch "$backup_dir/COMPLETE"
if [[ -n "${AAS_BACKUP_RESULT_FILE:-}" ]]; then
  printf '%s\n' "$backup_dir" > "$AAS_BACKUP_RESULT_FILE"
fi
printf 'Backup: %s\n' "$backup_dir"
