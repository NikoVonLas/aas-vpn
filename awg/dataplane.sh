#!/bin/sh
# Own the published UDP socket's network namespace independently of controller releases.
set -eu

marker=/awg-control/dataplane-netns
temporary="$marker.tmp"
readlink /proc/self/ns/net > "$temporary"
chmod 0640 "$temporary"
mv "$temporary" "$marker"
exec sleep 2147483647
