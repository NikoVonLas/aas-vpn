#!/usr/bin/env bash
# Consistent stopped-stack backup, including the actual image IDs and all volumes.
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
mkdir -p "$backup_dir"
docker compose config --format json > "$backup_dir/compose-resolved.json"
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
# The EXIT trap restarts the old stack even when archiving fails.
trap 'docker compose up -d --pull never >/dev/null' EXIT
docker compose stop
tar --exclude='./backups' --exclude='./.git' -czf "$backup_dir/project.tar.gz" .
while IFS=$'\t' read -r key volume; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  docker run --rm --network none -v "$volume:/volume:ro" -v "$backup_dir:/backup" alpine:3.22 \
    sh -c 'cd /volume && tar czf "/backup/volume-$1.tar.gz" .' sh "$key"
done < <(jq -r '.volumes | to_entries[] | [.key,.value.name] | @tsv' "$backup_dir/compose-resolved.json")
touch "$backup_dir/COMPLETE"
printf 'Backup: %s\n' "$backup_dir"
