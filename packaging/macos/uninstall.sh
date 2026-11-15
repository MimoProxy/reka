#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
OWNER=${1:?numeric owner UID required}
case "$OWNER" in ''|*[!0-9]*) exit 1;; esac
PLIST=/Library/LaunchDaemons/org.mimoproxy.reka.$OWNER.plist
if [ -f "$PLIST" ]; then launchctl bootout system "$PLIST"; rm "$PLIST"; fi
echo "Service stopped. State and binary retained for recovery or reinstallation."
