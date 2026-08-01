#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

jq empty config/sing-box.json
docker compose --env-file .env.example config --quiet
for script in scripts/*.sh; do bash -n "$script"; done
echo "Validation passed"
