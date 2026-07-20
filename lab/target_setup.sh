#!/usr/bin/env bash
#
# target_setup.sh - run ONCE on the Target Server (the DVWA victim) so a port
# scan leaves a "PORTSCAN " trace in the logs that Filebeat ships to ELK.
#
# nmap by itself does not write anything to the target's logs, so the Port
# Scan detection rule has nothing to match. This adds an iptables rule that
# LOGs a burst of new TCP connections (scanning behaviour) with the prefix
# the rule keys on, then makes sure Filebeat ships the kernel log.
#
# Run as root on the Target Server:  sudo ./target_setup.sh
#
set -euo pipefail

PREFIX="PORTSCAN "
HITCOUNT="${HITCOUNT:-20}"     # SYNs from one source within...
SECONDS_WINDOW="${SECONDS_WINDOW:-10}"   # ...this many seconds trips a log line

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 1; }

echo "[*] adding iptables PORTSCAN logging rule"
# idempotent: drop any previous copy first
iptables -D INPUT -p tcp --syn -m recent --name portscan --rcheck \
  --seconds "$SECONDS_WINDOW" --hitcount "$HITCOUNT" \
  -j LOG --log-prefix "$PREFIX" --log-level 4 2>/dev/null || true
iptables -D INPUT -p tcp --syn -m recent --name portscan --set 2>/dev/null || true

# record every new inbound TCP SYN against the "portscan" list, then LOG once
# the rate from a single source looks like a scan
iptables -A INPUT -p tcp --syn -m recent --name portscan --set
iptables -A INPUT -p tcp --syn -m recent --name portscan --rcheck \
  --seconds "$SECONDS_WINDOW" --hitcount "$HITCOUNT" \
  -j LOG --log-prefix "$PREFIX" --log-level 4

echo "[*] persisting the rule (best effort)"
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
elif command -v iptables-save >/dev/null 2>&1; then
  mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 || true
fi

# iptables LOG at level 4 (warning) goes to the kernel log. Make sure it lands
# in a file Filebeat is shipping.
KERN_LOG=/var/log/kern.log
[ -f "$KERN_LOG" ] || KERN_LOG=/var/log/syslog
echo "[*] kernel LOG target: $KERN_LOG"

echo
echo "[+] done. Verify after a scan with:"
echo "      sudo grep PORTSCAN $KERN_LOG | tail"
echo
echo "[!] Ensure Filebeat ships $KERN_LOG. In /etc/filebeat/filebeat.yml the"
echo "    system module or a log input must include it, e.g.:"
echo
echo "      - type: filestream"
echo "        id: kernlog"
echo "        paths: [ $KERN_LOG ]"
echo
echo "    then:  sudo filebeat modules enable system && sudo systemctl restart filebeat"
