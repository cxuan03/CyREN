# cyren-attacker : one lightweight image carrying every lab attack tool.
# One container runs ONE tool, selected at runtime by -e ATTACK=sqli|hydra|nmap|masscan
# (dispatched by /usr/local/bin/attack.sh). Build once, reuse for all 4 containers.

FROM debian:12-slim
# ^ small, stable base (~30MB before tools); Debian main has all six tools packaged.

ENV DEBIAN_FRONTEND=noninteractive
# ^ non-interactive apt so the build never blocks on a prompt.

# Packages installed in the single RUN below (kept in one layer + cache cleaned).
# Docker forbids inline '#' on a continued shell line, so each tool is documented here:
#   sqlmap        - SQL injection            -> the sqlmap (.120) container
#   hydra         - SSH brute force          -> the hydra  (.122) container
#   nmap          - TCP connect port scan    -> the nmap   (.123) container
#   masscan       - high-rate SYN port scan  -> the masscan(.124) container
#   medusa        - alternative brute-forcer -> available for variety (not in the default 4)
#   curl          - DVWA login + HTTP        -> used by the sqli entrypoint to get a session
#   iproute2      - provides `ip neigh`       -> masscan entrypoint resolves the target MAC
#   iputils-ping  - provides `ping`           -> populate the ARP cache before `ip neigh`
#   ca-certificates - TLS roots (harmless, future-proofing)
RUN apt-get update && apt-get install -y --no-install-recommends \
      sqlmap hydra nmap masscan medusa curl iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY passlist.txt /opt/passlist.txt
# ^ wrong-password list for the hydra/medusa SSH brute (only ever produces "Failed password").

COPY attack.sh /usr/local/bin/attack.sh
RUN chmod +x /usr/local/bin/attack.sh
# ^ the entrypoint dispatcher: reads $ATTACK/$TARGET/rate envs and runs the right tool.

ENTRYPOINT ["/usr/local/bin/attack.sh"]
# ^ so `docker run ... cyren-attacker` needs no command, just -e ATTACK=...
