#!/usr/bin/env bash
# CyREN blocklist sync — runs on the TARGET host (Ubuntu).
# Pulls the active block list from CyREN and enforces it with ipset+iptables.
#
#   - list-driven: whatever CyREN says is blocked, is blocked; an IP that
#     disappears from the list is unblocked on the next sync
#   - atomic: the new set is built aside and swapped in, the firewall is
#     never half-applied
#   - fail-safe: if CyREN is unreachable, the LAST list stays enforced
#   - whitelist: IPs in /etc/cyren/whitelist.txt are NEVER added, so the
#     target itself / the gateway / your admin IP cannot be locked out
set -euo pipefail

CONF=/etc/cyren/blocklist.conf
WL=/etc/cyren/whitelist.txt
SET=cyren_block
TMP=cyren_block_tmp

# CYREN_URL and TOKEN come from the config file (root-only, not in the repo)
# shellcheck source=/dev/null
source "$CONF"

# fetch the list; on ANY fetch/auth failure keep the current set and exit 0
LIST=$(curl -fsS --max-time 5 -H "X-CyREN-Token: ${TOKEN}" "${CYREN_URL}") || exit 0

# make sure both sets exist
ipset create "$SET" hash:ip -exist
ipset create "$TMP" hash:ip -exist
ipset flush "$TMP"

# fill the staging set: valid IPv4 only, whitelist always wins
while IFS= read -r ip; do
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
    if grep -qxF "$ip" "$WL" 2>/dev/null; then
        continue
    fi
    ipset add "$TMP" "$ip" -exist
done <<< "$LIST"

# atomic swap, then clear the staging set
ipset swap "$TMP" "$SET"
ipset flush "$TMP"

# ensure the single enforcement rule exists (idempotent; survives reboots
# because this script runs every few seconds via the systemd timer)
if ! iptables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null; then
    iptables -I INPUT 1 -m set --match-set "$SET" src -j DROP
fi
