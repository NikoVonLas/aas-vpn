#!/usr/bin/env bash
# Explicit operator action: restore the matching image + data backup as a unit.
set -Eeuo pipefail
# Serialize maintenance with watchdog; child backup inherits this lock.
if [[ "${AAS_MAINTENANCE_LOCKED:-}" != 1 ]]; then
  exec 9>/run/aas-vpn-watchdog.lock
  flock 9
  export AAS_MAINTENANCE_LOCKED=1
fi
main() {
cd "$(dirname "${BASH_SOURCE[0]}")/.."
backup_dir=$(cd "${1:?Usage: sudo scripts/rollback.sh /absolute/backup/path}" && pwd)
[[ -f "$backup_dir/COMPLETE" ]] || { echo 'Incomplete backup' >&2; exit 1; }
docker compose stop
tar -xzf "$backup_dir/project.tar.gz" -C .
docker image load -i "$backup_dir/images.tar"
while IFS=$'\t' read -r key volume; do
  [[ -f "$backup_dir/volume-$key.tar.gz" ]] || continue
  docker volume inspect "$volume" >/dev/null 2>&1 || docker volume create "$volume" >/dev/null
  docker run --rm --network none -v "$volume:/volume" -v "$backup_dir:/backup:ro" alpine:3.22 \
    sh -c 'find /volume -mindepth 1 -maxdepth 1 -exec rm -rf {} +; cd /volume; tar xzf "/backup/volume-$1.tar.gz"' sh "$key"
done < <(jq -r '.volumes | to_entries[] | [.key,.value.name] | @tsv' "$backup_dir/compose-resolved.json")
# Keep the image override active for watchdog and future systemd restarts.
cp "$backup_dir/images.json" compose.rollback.json
# shellcheck disable=SC1091
source .env
rollback_files=${COMPOSE_FILE:-compose.yml}
rollback_files=${rollback_files%:compose.rollback.json}
printf '\nCOMPOSE_FILE=%s:compose.rollback.json\n' "$rollback_files" >> .env
# Resolved Compose captures the exact pre-upgrade overlay and volume names.
docker compose -f "$backup_dir/compose-resolved.json" -f "$backup_dir/images.json" up -d --pull never --no-build --remove-orphans
}
main "$@"
