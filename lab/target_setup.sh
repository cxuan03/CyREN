#!/usr/bin/env bash
#
# target_setup.sh - run ONCE on the Target Server (the DVWA victim) so a port
# scan leaves a "PORTSCAN " trace in the logs that Filebeat ships to ELK, AND so
# the rule is re-applied automatically on every reboot.
#
# nmap/masscan by themselves write nothing to the target's logs, so the Port
# Scan detection rule has nothing to match. This adds an iptables rule that LOGs
# a burst of new TCP connections (scanning behaviour) with the prefix the rule
# keys on. To survive reboots it installs a tiny systemd oneshot service that
# re-applies the rule at boot - self-contained, so it does NOT depend on
# iptables-persistent/netfilter-persistent being installed and configured
# (the previous "best effort save" silently did nothing without that package).
#
# Run as root on the Target Server:  sudo ./target_setup.sh
#
set -euo pipefail

PREFIX="${PREFIX:-PORTSCAN }"
HITCOUNT="${HITCOUNT:-20}"                  # SYNs from one source within...
SECONDS_WINDOW="${SECONDS_WINDOW:-10}"      # ...this many seconds trips a log line

HELPER=/usr/local/sbin/cyren-portscan-rule.sh
UNIT=/etc/systemd/system/cyren-portscan.service

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 1; }

echo "[*] installing the PORTSCAN rule helper at $HELPER"
# The helper (re)applies the rule idempotently: delete any previous copy first,
# then add. Both this setup script and the boot-time systemd service call it, so
# the rule definition lives in exactly one place and re-runs never stack copies.
cat > "$HELPER" <<EOF
#!/usr/bin/env bash
# Installed by lab/target_setup.sh. Idempotently (re)applies the iptables
# PORTSCAN logging rule. Called at boot by cyren-portscan.service.
set -eu
PREFIX="$PREFIX"
HITCOUNT="$HITCOUNT"
SECONDS_WINDOW="$SECONDS_WINDOW"

# drop any previous copy first so re-runs do not stack duplicates
iptables -D INPUT -p tcp --syn -m recent --name portscan --rcheck \\
  --seconds "\$SECONDS_WINDOW" --hitcount "\$HITCOUNT" \\
  -j LOG --log-prefix "\$PREFIX" --log-level 4 2>/dev/null || true
iptables -D INPUT -p tcp --syn -m recent --name portscan --set 2>/dev/null || true

# record every new inbound TCP SYN against the "portscan" list, then LOG once
# the rate from a single source looks like a scan
iptables -A INPUT -p tcp --syn -m recent --name portscan --set
iptables -A INPUT -p tcp --syn -m recent --name portscan --rcheck \\
  --seconds "\$SECONDS_WINDOW" --hitcount "\$HITCOUNT" \\
  -j LOG --log-prefix "\$PREFIX" --log-level 4
EOF
chmod +x "$HELPER"

echo "[*] applying the rule now"
"$HELPER"

echo "[*] installing systemd service so the rule survives reboot"
cat > "$UNIT" <<EOF
[Unit]
Description=CyREN iptables PORTSCAN logging rule
# network-pre.target is the standard slot for firewall rules: applied before
# the network comes up, so no scan traffic is ever seen without the rule.
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$HELPER

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cyren-portscan.service
echo "[+] cyren-portscan.service enabled (re-applies the rule on every boot)"

# belt and braces: if iptables-persistent is present, save too. Harmless if not.
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
fi

# iptables LOG at level 4 (warning) goes to the kernel log. Make sure it lands
# in a file Filebeat is shipping.
KERN_LOG=/var/log/kern.log
[ -f "$KERN_LOG" ] || KERN_LOG=/var/log/syslog

echo
echo "[+] done. Verify:"
echo "      systemctl is-enabled cyren-portscan.service     # -> enabled"
echo "      sudo iptables -S INPUT | grep portscan          # rule present now"
echo "      sudo grep PORTSCAN $KERN_LOG | tail             # after a scan"
echo
echo "[!] Ensure Filebeat ships $KERN_LOG (system module or a filestream input),"
echo "    then:  sudo filebeat modules enable system && sudo systemctl restart filebeat"
