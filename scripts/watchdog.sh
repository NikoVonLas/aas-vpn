#!/bin/sh
set -u

cd "$(dirname "$0")/.." || exit 1
running_format='{{.State.Running}}'

state=/run/aas-vpn-watchdog.failures
exec 9>/run/aas-vpn-watchdog.lock
flock -n 9 || exit 0

router_healthy() {
  docker inspect --format '{{.State.Health.Status}}' sing-box 2>/dev/null | grep -qx healthy &&
  docker exec sing-box python -c "import json; assert json.load(open('/routing-status/status.json'))['running']" 2>/dev/null
  return $?
}

healthy() {
  docker inspect --format '{{.State.Health.Status}}' awg2 2>/dev/null | grep -qx healthy &&
  docker inspect --format "$running_format" adguard-home 2>/dev/null | grep -qx true &&
  router_healthy &&
  docker inspect --format "$running_format" aas-caddy 2>/dev/null | grep -qx true &&
  docker inspect --format "$running_format" aas-portal 2>/dev/null | grep -qx true &&
  docker inspect --format "$running_format" aas-auth-sync 2>/dev/null | grep -qx true
  return $?
}

if healthy; then
  rm -f "$state"
  exit 0
fi

failures=0
[ ! -r "$state" ] || read -r failures < "$state"
failures=$((failures + 1))
printf '%s\n' "$failures" > "$state"
logger -t aas-vpn-watchdog "health check failed ($failures)"
[ "$failures" -ge 2 ] || exit 0

# `up` alone does not restart an unhealthy running service.
if ! router_healthy; then
  docker compose restart sing-box || true
fi
if ! docker inspect --format '{{.State.Health.Status}}' awg2 2>/dev/null | grep -qx healthy; then
  docker compose restart awg2 || true
fi
timeout 90 docker compose up -d --pull never --remove-orphans || true
sleep 10
if healthy; then
  rm -f "$state"
  logger -t aas-vpn-watchdog "services recovered"
else
  logger -t aas-vpn-watchdog "automatic recovery failed"
fi
