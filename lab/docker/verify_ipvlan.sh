#!/usr/bin/env bash
#
# verify_ipvlan.sh - MINIMAL proof, before building the full distributed
# attacker set, that a Docker ipvlan L2 container reaches the VirtualBox
# Host-Only Target with its OWN source IP (no NAT).
#
# It creates ONE ipvlan L2 network on the Kali Host-Only interface and runs ONE
# throwaway container at .120, then runs three checks. If check 3 shows the
# container IP (.120) as the Apache client - not the Kali host IP - the network
# design is proven and we can scale to four attacker containers. If not, fall
# back to the IP-alias scripts (attack_dvwa.sh / attack_multitool.sh).
#
# Run on the Kali VM (Docker must be installed - see lab/docker/README.md):
#   sudo IFACE=eth0 TARGET=192.168.56.101 ./verify_ipvlan.sh
#
set -uo pipefail

IFACE="${IFACE:-eth0}"                 # Kali's Host-Only interface (parent)
TARGET="${TARGET:-192.168.56.101}"     # DVWA target
GATEWAY="${GATEWAY:-192.168.56.1}"     # Host-Only gateway (VirtualBox host)
SUBNET="${SUBNET:-192.168.56.0/24}"
IPRANGE="${IPRANGE:-192.168.56.120/28}" # Docker allocates only .120-.135 here
CIP="${CIP:-192.168.56.120}"           # the one test container's IP
NET="${NET:-hostonly_attackers}"
IMAGE="${IMAGE:-nicolaka/netshoot}"    # already ships ping + curl (+ nmap)
PROBE="cyren_probe=ipvlan_${CIP}"      # unique tag to find in the Apache log

c_ok()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_inf() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_err() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

command -v docker >/dev/null 2>&1 || { c_err "docker not installed - see lab/docker/README.md"; exit 1; }

# safety: private lab target only
case "$TARGET" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) : ;;
  *) c_err "TARGET $TARGET is not a private lab address. Refusing."; exit 1 ;;
esac

# The image is pulled by the Docker daemon over Kali's normal (NAT) internet
# BEFORE the container joins the isolated Host-Only network, which has no
# internet - so do it now, explicitly.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  c_inf "pulling $IMAGE (needs Kali's normal internet, not the attack network)"
  docker pull "$IMAGE" || { c_err "pull failed - set IMAGE= to a locally present image with ping+curl"; exit 1; }
fi

# create the ipvlan L2 network (idempotent)
if docker network inspect "$NET" >/dev/null 2>&1; then
  c_inf "ipvlan network $NET already exists (reusing)"
else
  c_inf "creating ipvlan L2 network $NET on parent $IFACE"
  docker network create -d ipvlan \
    --subnet "$SUBNET" --gateway "$GATEWAY" --ip-range "$IPRANGE" \
    -o parent="$IFACE" -o ipvlan_mode=l2 "$NET" \
    || { c_err "network create failed (is $IFACE the Host-Only NIC? is the ipvlan module loaded? try: sudo modprobe ipvlan)"; exit 1; }
fi

run() { docker run --rm --network "$NET" --ip "$CIP" "$IMAGE" "$@"; }

echo
c_inf "=== check 1/3: container ($CIP) reaches the Target at layer 2 (ping) ==="
if run ping -c3 -W2 "$TARGET"; then c_ok "ping OK"; else
  c_err "ping FAILED - container cannot reach the Host-Only segment. See README troubleshooting."; fi

echo
c_inf "=== check 2/3: container reaches DVWA over HTTP ==="
if run curl -s -o /dev/null -w 'HTTP %{http_code}\n' "http://$TARGET/dvwa/"; then
  c_ok "HTTP reachable (302 to login is normal)"; else
  c_err "HTTP FAILED"; fi

echo
c_inf "=== check 3/3: prove the Target sees $CIP as the client (NO NAT) ==="
run curl -s -o /dev/null "http://$TARGET/dvwa/?$PROBE"
c_ok "sent a tagged request from the container."
echo
echo "  Now confirm ON THE TARGET (192.168.56.101):"
echo "      sudo grep '$PROBE' /var/log/apache2/access.log | tail -1"
echo
echo "  PASS if the line STARTS with $CIP  ->  ipvlan works, no NAT, scale to 4."
echo "  FAIL if it starts with Kali's Host-Only IP -> NAT happened; see README,"
echo "       or fall back to the IP-alias scripts."
