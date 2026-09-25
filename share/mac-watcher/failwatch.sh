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

# Only one watcher may run, or every failed attempt is reported once per
# watcher. Stop any other instance of this user, including orphans left by
# older versions, which ran the loop in a pipeline subshell that outlived
# the agent when launchd stopped it.
stop_other_watchers() {
    local pid pgid
    for pid in $(pgrep -u "$(id -u)" -f 'mac-watcher/failwatch\.sh'); do
        [ "$pid" = "$$" ] && continue
        # only a bash running a watcher script, never e.g. an editor on the file
        [[ "$(ps -o command= -p "$pid" 2>/dev/null)" =~ ^(/bin/)?bash\ [^\ ]*mac-watcher/failwatch\.sh$ ]] || continue
        # its log stream: a child, or a sibling in the same process group (orphans)
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        pkill -TERM -P "$pid" -x log 2>/dev/null
        [ -n "$pgid" ] && pkill -TERM -g "$pgid" -x log 2>/dev/null
        kill -TERM "$pid" 2>/dev/null && log_msg "stopped other watcher (pid $pid)"
    done
}
stop_other_watchers

# Read `log stream` through a FIFO rather than a pipeline, so the loop runs
# in this process and the stream can be stopped with it. (/bin/bash 3.2
# does not reliably report the pid of a process substitution.)
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mac-watcher-failwatch.XXXXXX")" || exit 1
FIFO="$WORK_DIR/log.fifo"
mkfifo -m 600 "$FIFO" || exit 1
STREAM_PID=""

cleanup() {
    [ -n "$STREAM_PID" ] && kill "$STREAM_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'log_msg "stopping (signal)"; exit 0' TERM INT HUP

/usr/bin/log stream --style syslog --predicate '
  process == "loginwindow" AND (
    eventMessage CONTAINS "INCORRECT password" OR
    eventMessage CONTAINS "APEventTouchIDNoMatch" OR
    eventMessage CONTAINS "Failed to authenticate user")' > "$FIFO" 2>&1 &
STREAM_PID=$!

log_msg "failwatch started (pid $$, log stream pid $STREAM_PID), monitor: $MONITOR"

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
done < "$FIFO"

# log stream exited; launchd (KeepAlive) restarts the agent
log_msg "log stream ended, exiting"
exit 1
