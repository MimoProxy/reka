#!/bin/sh
# Requires explicit permission to interrupt this Mac's Wi-Fi for eight seconds.
set -eu
IFACE=${1:?Wi-Fi interface required}
case "$(/usr/sbin/networksetup -getairportpower "$IFACE")" in
  *': On') ;;
  *) echo 'Wi-Fi must already be on; refusing to change its baseline.' >&2; exit 1;;
esac
restore() { /usr/sbin/networksetup -setairportpower "$IFACE" on; }
trap restore EXIT HUP INT TERM
/usr/sbin/networksetup -setairportpower "$IFACE" off
/usr/sbin/networksetup -getairportpower "$IFACE"
sleep 8
restore
sleep 3
/usr/sbin/networksetup -getairportpower "$IFACE"
