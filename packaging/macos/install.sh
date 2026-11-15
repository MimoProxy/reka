#!/bin/sh
# Install one root service, with control access granted only to this UID.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
OWNER=${1:?numeric owner UID required}
case "$OWNER" in ''|*[!0-9]*) echo 'Owner must be a numeric UID.' >&2; exit 1;; esac
SRC=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
[ -x "$SRC/reka" ] || SRC="$SRC/bin"
[ -x "$SRC/reka" ] || { echo 'Missing reka binary.' >&2; exit 1; }
LABEL=org.mimoproxy.reka.$OWNER
PLIST=/Library/LaunchDaemons/$LABEL.plist
[ ! -e "$PLIST" ] || { echo 'Service already installed; uninstall before upgrading.' >&2; exit 1; }
ROOT="/Library/Application Support/Reka/$OWNER"
BIN="/Library/Application Support/Reka/bin/$OWNER"
RUN=/var/run/reka/$OWNER
install -d -m 700 "$ROOT" "$BIN"
install -d -m 755 /var/run/reka "$RUN"
install -m 755 "$SRC/reka" "$BIN/reka"
cat > "$BIN/run-service.sh" <<EOF
#!/bin/sh
set -eu
/usr/bin/install -d -m 755 -o root -g wheel /var/run/reka "$RUN"
exec "$BIN/reka" -state-root "$ROOT" -control "unix://$RUN/control.sock" -owner "$OWNER" -edit-dir -
EOF
chmod 755 "$BIN/run-service.sh"
chown root:wheel "$BIN/run-service.sh"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>$BIN/run-service.sh</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>5</integer>
<key>ExitTimeOut</key><integer>60</integer>
</dict></plist>
EOF
chmod 644 "$PLIST"
chown root:wheel "$PLIST" "$BIN/reka"
launchctl bootstrap system "$PLIST"
echo "Installed. Control: unix://$RUN/control.sock (UID $OWNER). Network mode defaults to off."
