#!/bin/sh
set -u

state=/run/aas-vpn-watchdog.failures
exec 9>/run/aas-vpn-watchdog.lock
flock -n 9 || exit 0

healthy() {
  docker inspect --format '{{.State.Health.Status}}' awg-easy 2>/dev/null | grep -qx healthy &&
  docker inspect --format '{{.State.Running}}' adguard-home 2>/dev/null | grep -qx true &&
  docker inspect --format '{{.State.Running}}' sing-box 2>/dev/null | grep -qx true &&
  docker inspect --format '{{.State.Running}}' caddy 2>/dev/null | grep -qx true
  docker inspect --format '{{.State.Running}}' aas-portal 2>/dev/null | grep -qx true
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

timeout 90 docker compose -f /opt/aas-vpn/compose.yml up -d --remove-orphans || true
sleep 10
if healthy; then
  rm -f "$state"
  logger -t aas-vpn-watchdog "services recovered"
else
  logger -t aas-vpn-watchdog "automatic recovery failed"
fi
