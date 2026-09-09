#!/bin/sh
set -eu
# Install before wg-easy brings up wg0. RETURN precedes its MASQUERADE.
# Mark only decrypted client packets, preserving their source for sing-box.
iptables -t mangle -C PREROUTING -i wg0 -j MARK --set-xmark 0xa450/0xffff 2>/dev/null || \
  iptables -t mangle -I PREROUTING 1 -i wg0 -j MARK --set-xmark 0xa450/0xffff
iptables -t nat -C POSTROUTING -m mark --mark 0xa450/0xffff -j RETURN 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -m mark --mark 0xa450/0xffff -j RETURN
# Docker daemon restart does not honor Compose depends_on. On every boot wait
# for a guard installed in this kernel, not a stale status file from yesterday.
until node -e 'const fs=require("fs"); try { const s=JSON.parse(fs.readFileSync("/routing-status/status.json")); process.exit(s.boot_id===fs.readFileSync("/proc/sys/kernel/random/boot_id","utf8").trim() && Date.now()/1000-s.updated_at<45 ? 0:1); } catch { process.exit(1); }'; do
  sleep 2
done
exec /usr/bin/dumb-init node server/index.mjs
