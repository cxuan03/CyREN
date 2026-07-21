#!/usr/bin/env bash
#
# benign_traffic.sh - generate NORMAL user traffic against the CyREN lab DVWA
# target, so the triage classifier has negative ("benign / non-threat")
# samples alongside the attack traffic from attack_dvwa.sh.
#
#   Source  : this host, aliased to a dedicated benign IP (default .160)
#   Target  : DVWA on the isolated Host-Only network (default 192.168.56.101)
#
# It produces two kinds of benign traffic:
#   1. Baseline browsing - login, home, about, instructions, static assets.
#      These do NOT match any detection rule: pure normal logs in ELK.
#   2. Legitimate use of the vulnerability demo pages - id=1, name=John,
#      ping 127.0.0.1 (no metacharacters), include.php - at a HUMAN pace.
#      With path-based rules these trip an alert, but with no attack payload
#      and a low request rate they are FALSE POSITIVES: exactly the negative
#      samples that teach the classifier to separate true from false positives.
#   3. A normal SSH login with the CORRECT password (needs sshpass + creds):
#      logs "Accepted password", not "Failed password", so it never trips the
#      brute-force rule - a benign SSH sample.
#
# Everything comes from one dedicated source IP (default 192.168.56.160) so the
# benign events are trivial to filter and label as benign in the training set.
#
# SAFETY: only runs against a private (RFC1918) lab address. Use exclusively on
# infrastructure you own and are authorised to test.
#
# Usage:
#   sudo ./benign_traffic.sh                       # web browsing, 20 rounds
#   sudo ROUNDS=40 ./benign_traffic.sh             # more volume
#   sudo SSH_USER=labuser SSH_PASS=Labpass123 ./benign_traffic.sh   # + normal SSH
#   sudo ./benign_traffic.sh --only web            # web only (web|ssh)
#   sudo ./benign_traffic.sh --yes                 # skip confirmation
#
set -uo pipefail

# ----------------------------------------------------------------- config
TARGET="${TARGET:-192.168.56.101}"
IFACE="${IFACE:-eth0}"
BENIGN_IP="${BENIGN_IP:-192.168.56.160}"     # dedicated benign source
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"
ROUNDS="${ROUNDS:-20}"
THINK_MIN="${THINK_MIN:-1}"                   # seconds of "human" pause...
THINK_MAX="${THINK_MAX:-4}"                   # ...between requests
# normal SSH login (leave unset to skip); needs a real account on the target
SSH_USER="${SSH_USER:-}"
SSH_PASS="${SSH_PASS:-}"

COOKIE_JAR="$(mktemp)"
ONLY=""
ASSUME_YES=0

# ------------------------------------------------------------- pretty print
c_ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }
phase()  { printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }

# --------------------------------------------------------------- arg parse
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --yes)  ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) c_err "unknown argument: $1"; exit 2 ;;
  esac
done

# ------------------------------------------------------------ safety checks
case "$TARGET" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
  *) c_err "TARGET $TARGET is not a private lab address. Refusing to run."; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || { c_err "missing tool: curl (apt install curl)"; exit 1; }
if [ "$(id -u)" -ne 0 ]; then
  c_err "run as root (needed for the source-IP alias and route): sudo $0"; exit 1
fi

echo
c_warn "CyREN benign-traffic generator"
c_warn "  source : $(hostname) via $IFACE, aliased to $BENIGN_IP"
c_warn "  target : $TARGET (DVWA)"
c_warn "  rounds : $ROUNDS   ssh: $([ -n "$SSH_USER" ] && echo "$SSH_USER@target" || echo "disabled")"
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Generate normal user traffic against $TARGET? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { c_info "aborted."; exit 0; }
fi

# --------------------------------------------------- source-IP aliasing
setup_alias() {
  ip addr add "$BENIGN_IP/24" dev "$IFACE" 2>/dev/null && c_info "added alias $BENIGN_IP" || true
  ip route replace "$TARGET" dev "$IFACE" src "$BENIGN_IP"
  c_info "benign source IP: $BENIGN_IP"
}
cleanup() {
  c_info "cleaning up alias and route"
  ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  ip addr del "$BENIGN_IP/24" dev "$IFACE" 2>/dev/null || true
  rm -f "$COOKIE_JAR" 2>/dev/null || true
}
trap cleanup EXIT

# realistic pause between requests ($RANDOM seeds awk so each call varies)
think() { sleep "$(awk -v a="$THINK_MIN" -v b="$THINK_MAX" -v s="$RANDOM" \
                    'BEGIN{srand(s);printf "%.1f", a+rand()*(b-a)}')"; }

UA="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
get() { curl -s -A "$UA" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null "$@"; }

# ------------------------------------------------------- DVWA normal login
dvwa_login() {
  local t
  t="$(curl -s -A "$UA" -c "$COOKIE_JAR" "http://$TARGET/dvwa/login.php" \
       | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -A "$UA" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null \
       --data "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" \
       "http://$TARGET/dvwa/login.php"
  local sid
  sid="$(grep -i PHPSESSID "$COOKIE_JAR" | awk '{print $NF}' | tail -1)"
  [ -n "$sid" ] || { c_err "DVWA login failed. Is DVWA up at http://$TARGET/dvwa/ ?"; return 1; }
  c_ok "logged in to DVWA as $DVWA_USER (normal login)"
}

# ------------------------------------------------------------ benign web
# pages that match NO detection rule -> pure normal baseline logs
BASELINE_PAGES=(
  "dvwa/index.php" "dvwa/about.php" "dvwa/instructions.php"
  "dvwa/security.php" "dvwa/phpinfo.php" "dvwa/ids_log.php"
  "dvwa/dvwa/css/main.css" "dvwa/dvwa/js/dvwaPage.js"
  "dvwa/dvwa/images/logo.png" "dvwa/favicon.ico"
)
# legitimate use of the demo pages: same paths an attacker uses, but with
# harmless inputs and at a human pace -> false-positive (benign) samples
legit_module_visit() {
  case $((RANDOM % 4)) in
    0) get "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" ;;   # a real user checks id 1
    1) get -G --data-urlencode "name=John" --data "Submit=Submit" \
           "http://$TARGET/dvwa/vulnerabilities/xss_r/" ;;                     # greets "John", no script
    2) curl -s -A "$UA" -b "$COOKIE_JAR" -o /dev/null \
           --data-urlencode "ip=127.0.0.1" --data "Submit=Submit" \
           "http://$TARGET/dvwa/vulnerabilities/exec/" ;;                      # pings localhost, no ; | &
    3) get "http://$TARGET/dvwa/vulnerabilities/fi/?page=include.php" ;;       # opens the intended page
  esac
}

benign_web() {
  phase "Benign web browsing ($ROUNDS rounds) from $BENIGN_IP"
  dvwa_login || return 1
  local i
  for i in $(seq 1 "$ROUNDS"); do
    # a couple of ordinary page views
    get "http://$TARGET/${BASELINE_PAGES[$((RANDOM % ${#BASELINE_PAGES[@]}))]}"; think
    get "http://$TARGET/${BASELINE_PAGES[$((RANDOM % ${#BASELINE_PAGES[@]}))]}"; think
    # roughly every 3rd round, a legitimate visit to a demo page (FP sample)
    if [ $((i % 3)) -eq 0 ]; then legit_module_visit; think; fi
    printf '\r  round %d/%d' "$i" "$ROUNDS"
  done
  echo
  # a normal logout/login cycle
  get "http://$TARGET/dvwa/logout.php"; think; dvwa_login >/dev/null || true
  c_ok "benign web traffic sent"
}

# ------------------------------------------------------------ normal SSH
benign_ssh() {
  phase "Normal SSH login from $BENIGN_IP"
  if [ -z "$SSH_USER" ] || [ -z "$SSH_PASS" ]; then
    c_warn "SSH_USER/SSH_PASS not set - skipping SSH. Set them to a real account:"
    c_warn "  sudo SSH_USER=labuser SSH_PASS=... ./benign_traffic.sh --only ssh"
    return 0
  fi
  command -v sshpass >/dev/null 2>&1 || { c_warn "sshpass not installed (apt install sshpass); skipping SSH"; return 0; }
  local n
  for n in 1 2 3; do
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
      "$SSH_USER@$TARGET" 'whoami; uptime; ls -la ~ >/dev/null; echo ok' \
      >/dev/null 2>&1 && c_ok "SSH session $n ok (Accepted password)" \
      || c_warn "SSH session $n failed (check SSH_USER/SSH_PASS and sshd)"
    think
  done
  c_ok "benign SSH traffic sent"
}

# ------------------------------------------------------------------- run
setup_alias
[ -z "$ONLY" ] || [ "$ONLY" = "web" ] && benign_web
[ -z "$ONLY" ] || [ "$ONLY" = "ssh" ] && benign_ssh

phase "Done"
c_ok "Benign traffic generated from $BENIGN_IP."
c_info "In ELK/CyREN, events from $BENIGN_IP are benign; label them as"
c_info "false positives / benign when building the training set (see README_lab.md)."
