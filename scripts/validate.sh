#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

jq empty config/sing-box.json
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example -f compose.yml -f examples/compose.external.yml config --quiet
python3 -m compileall -q portal router awg tests
for script in scripts/*.sh; do bash -n "$script"; done
if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh; fi
if [[ "${1:-}" == "--tests" ]]; then
  "${PYTHON:-python3}" -m pytest -q tests
fi
echo "Validation passed"
