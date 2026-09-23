#!/bin/bash
#=================================================================
# MAC-WATCHER FAILED-LOGIN WATCHER
#
# Streams loginwindow's unified log continuously and runs monitor.sh
# (photo, screenshot, location, email) on every wrong password or
# wrong fingerprint at the lock screen.
#
# Unlike the sleepwatcher .wakeup hook this does not depend on a
# sleep/wake transition, so it also covers a locked screen on a Mac
# that never sleeps (on AC power, display sleep only, DarkWake).
#
# Installed as a LaunchAgent by `mac-watcher --failwatch install`.
#=================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR="$SCRIPT_DIR/monitor.sh"

# One capture per burst of failed attempts (seconds)
COOLDOWN="${MAC_WATCHER_FAILWATCH_COOLDOWN:-60}"
last_trigger=0

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*"
}

if [ ! -x "$MONITOR" ]; then
    log_msg "Error: monitor script not found or not executable: $MONITOR"
    exit 1
fi

log_msg "failwatch started (pid $$), monitor: $MONITOR"

/usr/bin/log stream --style syslog --predicate '
  process == "loginwindow" AND (
    eventMessage CONTAINS "INCORRECT password" OR
    eventMessage CONTAINS "APEventTouchIDNoMatch" OR
    eventMessage CONTAINS "Failed to authenticate user")' 2>&1 |
while IFS= read -r line; do
    case "$line" in
        # The stream header echoes the predicate text, which contains the markers
        *"Filtering the log data"*) continue ;;
        *APEventTouchIDNoMatch*) method="fingerprint/touch ID" ;;
        *"INCORRECT password"*|*"Failed to authenticate user"*) method="password" ;;
        *) continue ;;
    esac

    log_msg "failed unlock attempt ($method)"

    now=$(date +%s)
    if (( now - last_trigger >= COOLDOWN )); then
        last_trigger=$now
        log_msg "running monitor"
        MAC_WATCHER_TRIGGER="$method" "$MONITOR" >/dev/null 2>&1 &
    fi
done

# log stream exited; launchd (KeepAlive) restarts the agent
log_msg "log stream ended, exiting"
exit 1
