#!/bin/bash
# Unit tests for the security-relevant helpers in monitor.sh and config.sh.
# The functions are extracted from the scripts and run in isolation: nothing is
# captured, sent or deleted outside a temporary directory.
#
# Usage: tests/test_security.sh   (or: make test)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITOR="$ROOT/share/mac-watcher/monitor.sh"
CONFIG_SH="$ROOT/share/mac-watcher/config.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
check() {
    if eval "$2"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "FAIL: $1"
    fi
}

# Print the definition of function $2 from file $1
extract() {
    awk -v f="$2" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}$/ {exit}' "$1"
}

for f in html_escape sanitize_coordinate save_json_debug build_email_payload \
    send_email_payload generate_html_initial_email generate_html_followup_email run_auto_delete; do
    extract "$MONITOR" "$f"
done > "$WORK/monitor_funcs.sh"
for f in config_quote mask_secret save_configuration; do
    extract "$CONFIG_SH" "$f"
done > "$WORK/config_funcs.sh"
source "$WORK/monitor_funcs.sh"
source "$WORK/config_funcs.sh"

#-----------------------------------------------------------------
# HTML escaping of network-provided values
#-----------------------------------------------------------------
TARGET_DIR="$WORK/target"
mkdir -p "$TARGET_DIR"
EMAIL_FROM='from@example.com'
EMAIL_TO='to@example.com'
DEBUG_EMAIL_JSON=no
LOCATION_ENABLED=yes NETWORK_INFO_ENABLED=yes WEBCAM_ENABLED=yes
SCREENSHOT_ENABLED=yes FOLLOWUP_SCREENSHOT_ENABLED=yes

check "html_escape escapes & < > \" '" \
    '[ "$(html_escape "<a href=\"x\">&'"'"'")" = "&lt;a href=&quot;x&quot;&gt;&amp;&#39;" ]'
check "numeric coordinates are kept" \
    '[ "$(sanitize_coordinate 44.4268)" = 44.4268 ] && [ "$(sanitize_coordinate -26.1)" = -26.1 ]'
check "non-numeric coordinates are dropped" \
    '[ "$(sanitize_coordinate "1&evil=1")" = "Not available" ]'

cat > "$TARGET_DIR/location_output.txt" <<'EOF'
Locality: <img src=x onerror=alert(1)>
Latitude: 1"><script>x</script>
Longitude: 2
WiFi SSID: <b>evil</b>","bcc":"attacker@example.com
Public IP Address: 1.2.3.4
EOF
html=$(generate_html_initial_email "user" "10:00" "10:01")
check "initial email: no raw injected tags" '! grep -q -E "<img src=x|<script>|<b>evil" <<<"$html"'
check "initial email: SSID shown escaped" 'grep -q "&lt;b&gt;evil&lt;/b&gt;" <<<"$html"'
check "initial email: injected latitude not in map link" '! grep -q "maps.apple.com/?q=1\"" <<<"$html"'
followup=$(generate_html_followup_email "user" "10:02")
check "follow-up email: no raw injected tags" '! grep -q -E "<img src=x|<script>" <<<"$followup"'

#-----------------------------------------------------------------
# JSON payload
#-----------------------------------------------------------------
printf 'JPEGDATA' > "$TARGET_DIR/photo.jpg"
: > "$TARGET_DIR/empty.jpg"
payload="$TARGET_DIR/.temp_email.json"
build_email_payload "$payload" 'subject "quoted"' text $'line1\n\\",\"bcc\":\"attacker@example.com\n' \
    "webcam.jpg=$TARGET_DIR/photo.jpg" "screen.jpg=$TARGET_DIR/empty.jpg" "missing.jpg="
check "payload is valid JSON" 'jq -e . "$payload" >/dev/null'
check "body cannot add keys (no bcc)" '[ "$(jq -r "has(\"bcc\")" "$payload")" = false ]'
check "text body preserved" '[ "$(jq -r .text "$payload" | head -1)" = line1 ]'
check "only non-empty attachments, content intact" \
    '[ "$(jq ".attachments | length" "$payload")" = 1 ] && [ "$(jq -r ".attachments[0].content" "$payload" | base64 -d)" = JPEGDATA ]'
check "no debug copy by default" '[ ! -e "$TARGET_DIR/debug_initial_email.json" ]'

DEBUG_EMAIL_JSON=yes build_email_payload "$TARGET_DIR/.temp_followup.json" s html "<p>x</p>" >/dev/null
check "debug copy when DEBUG_EMAIL_JSON=yes" '[ -f "$TARGET_DIR/debug_followup_email.json" ]'
check "no attachments key without attachments" \
    '[ "$(jq "has(\"attachments\")" "$TARGET_DIR/.temp_followup.json")" = false ]'

#-----------------------------------------------------------------
# API key handling
#-----------------------------------------------------------------
RESEND_API_KEY='re_TESTKEY123456'
curl() { printf 'ARGV:%s\n' "$*"; printf 'STDIN:'; cat; printf '200'; }
out=$(send_email_payload "$payload")
unset -f curl
check "API key not on curl command line" '! grep "^ARGV:" <<<"$out" | grep -q re_TESTKEY123456'
check "API key passed on stdin" 'grep -q "STDIN:header = \"Authorization: Bearer re_TESTKEY123456\"" <<<"$out"'
check "HTTP status is the last 3 characters" '[ "${out: -3}" = 200 ]'
check "mask_secret hides the key" '[ "$(mask_secret re_TESTKEY123456)" = "re_TE…3456" ]'

#-----------------------------------------------------------------
# Config file writing
#-----------------------------------------------------------------
CONFIG_FILE="$WORK/monitor.conf"
CURRENT_USER=tester SUCCESS= NC= ERROR=
evil_dir="/Users/x/Pic \$(touch $WORK/PWNED) \`touch $WORK/PWNED2\` \"q\" \\back"
(
    umask 022
    BASE_DIR="$evil_dir" LOCATION_ENABLED=yes INITIAL_DELAY='2; touch x' FOLLOWUP_DELAY=25 \
        AUTO_DELETE_DAYS=365 EMAIL_ACTIVE_WINDOWS=$'09:00-17:00\nINJECTED=1' \
        save_configuration >/dev/null
)
check "config file is 0600" '[ "$(stat -f %Sp "$CONFIG_FILE")" = "-rw-------" ]'
check "config values round-trip exactly" '( source "$CONFIG_FILE"; [ "$BASE_DIR" = "$evil_dir" ] )'
check "sourcing config runs no code" '( source "$CONFIG_FILE" ); [ ! -e "$WORK/PWNED" ] && [ ! -e "$WORK/PWNED2" ]'
check "newline cannot inject a variable" '( source "$CONFIG_FILE"; [ -z "${INJECTED-}" ] )'
check "non-numeric delay becomes 0" '( source "$CONFIG_FILE"; [ "$INITIAL_DELAY" = 0 ] )'
check "setup.sh LOCATION_ENABLED grep still matches" 'grep -q "LOCATION_ENABLED=\"yes\"" "$CONFIG_FILE"'

#-----------------------------------------------------------------
# Auto-delete guard
#-----------------------------------------------------------------
home="$(cd "$WORK" && pwd -P)/home"
mkdir -p "$home/Pictures/.access/2020/January/d" "$home/Pictures/.access/notes" "$home/Documents"
for f in "$home/Pictures/.access/2020/January/d/old.jpg" "$home/Pictures/.access/notes/keep.txt" \
    "$home/Documents/old.doc" "$home/Pictures/old.png"; do
    echo x > "$f"
    touch -t 202001010000 "$f"
done
(
    export HOME="$home"
    AUTO_DELETE_ENABLED=yes AUTO_DELETE_DAYS=30
    cd "$home/Pictures"
    for BASE_DIR in "$home" "$home/" / "" relative ".access" "$home/Pictures" "$home/Pictures/.access"; do
        run_auto_delete >/dev/null
    done
)
check "auto-delete removes old captures" '[ ! -e "$home/Pictures/.access/2020/January/d/old.jpg" ]'
check "auto-delete keeps non-capture files in BASE_DIR" '[ -e "$home/Pictures/.access/notes/keep.txt" ]'
check "auto-delete never touches the rest of HOME" '[ -e "$home/Documents/old.doc" ] && [ -e "$home/Pictures/old.png" ]'

echo "security tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
