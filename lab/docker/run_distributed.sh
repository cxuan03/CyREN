#!/usr/bin/env bash
# run_distributed.sh - staggered launch / stop of the 4 distributed-attack
# containers, so they do NOT all hit the target at the same instant (realistic +
# gentle, not a DDoS). Combine with the per-tool rate limits baked into attack.sh.
#
#   ./run_distributed.sh up          # start the 4 containers, GAP seconds apart
#   GAP=120 ./run_distributed.sh up  # wider spacing
#   ./run_distributed.sh stop        # stop + remove them
#   ./run_distributed.sh logs        # follow all container logs
#
# Requires: the cyren-attacker image built and the hostonly_attackers ipvlan
# network created (see DISTRIBUTED_ATTACK_GUIDE.md steps 1-2).
set -uo pipefail

cd "$(dirname "$0")"                 # run from lab/docker/ so compose finds the yml
GAP="${GAP:-60}"                     # seconds between starting each container
ORDER=(atk-sqlmap atk-nmap atk-masscan atk-hydra)   # web first, brute last

case "${1:-up}" in
  up)
    for s in "${ORDER[@]}"; do
      echo "[*] starting $s"
      docker compose up -d "$s"
      if [ "$s" != "${ORDER[-1]}" ]; then
        echo "    staggering: waiting ${GAP}s before the next source"
        sleep "$GAP"
      fi
    done
    echo "[+] all 4 sources launched. Follow with: ./run_distributed.sh logs"
    ;;
  stop|down)
    docker compose down
    echo "[+] stopped and removed the 4 containers (network is left intact)"
    ;;
  logs)
    docker compose logs -f
    ;;
  *)
    echo "usage: $0 {up|stop|logs}   (GAP=<seconds> for spacing)"; exit 2 ;;
esac
