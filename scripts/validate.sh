#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

jq empty config/sing-box.json
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example -f compose.yml -f compose.edge.yml config --quiet
python3 -m compileall -q portal router tests
sh -n awg/start.sh
for script in scripts/*.sh; do bash -n "$script"; done
if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh awg/start.sh; fi
if [[ "${1:-}" == "--tests" ]]; then
  "${PYTHON:-python3}" -m pytest -q tests
fi
echo "Validation passed"
