# CyREN lab — Docker distributed attackers

Goal: run each attacker as its own lightweight Docker container with its **own
independent source IP** on the VirtualBox Host-Only segment, so the DVWA Target
(and CyREN) see a genuinely multi-source distributed attack — more convincing
than the IP-alias approach, without touching any core code.

**Runs on the Kali VM** (Linux, already on the Host-Only net). Do **not** use
Docker Desktop on the Windows host — its WSL2 network cannot reliably reach the
`vboxnet0` Host-Only segment.

The IP-alias scripts (`../attack_dvwa.sh`, `../attack_multitool.sh`) stay as a
**fallback**. This is additive.

---

## Stage 0 — prove the network first (do this before anything else)

If a container cannot reach the Host-Only Target with its own IP, the whole
approach is moot. Verify with ONE container before building four.

### ① Install Docker on Kali

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo modprobe ipvlan            # ipvlan L2 driver (usually already loaded)
sudo docker run --rm hello-world   # sanity: needs Kali's normal internet
```

### ② Minimal version — one ipvlan network + one container

```bash
scp lab/docker/verify_ipvlan.sh user@<kali>:/tmp/
sudo IFACE=eth0 TARGET=192.168.56.101 bash /tmp/verify_ipvlan.sh
```

`IFACE` must be Kali's **Host-Only** interface (the one that reaches
`192.168.56.101`). The script creates the ipvlan L2 network
`hostonly_attackers` (`--subnet 192.168.56.0/24`, `--ip-range
192.168.56.120/28`, `parent=eth0`, `ipvlan_mode=l2`) and runs one throwaway
`nicolaka/netshoot` container at **192.168.56.120**.

### ③ Three-step connectivity verification

The script runs checks 1 and 2 and sends a tagged request for check 3:

1. **L2 reachability** — container pings `192.168.56.101`.
2. **HTTP reachability** — container gets DVWA (`302` to login is fine).
3. **No-NAT proof (the decisive one)** — the container sends
   `GET /dvwa/?cyren_probe=ipvlan_192.168.56.120`; then on the **Target**:

   ```bash
   sudo grep 'cyren_probe=ipvlan_192.168.56.120' /var/log/apache2/access.log | tail -1
   ```

   - **PASS**: the line starts with `192.168.56.120` (the container IP) → ipvlan
     L2 works, no NAT, each container is an independent source. Proceed to scale.
   - **FAIL**: the line starts with Kali's Host-Only IP → traffic was NAT'd; see
     troubleshooting, or fall back to the IP-alias scripts.

---

## Troubleshooting (if a check fails)

- **ping fails / network create errors**: confirm `IFACE` is the Host-Only NIC
  (`ip -br addr` — the one with a `192.168.56.x` address); `sudo modprobe ipvlan`.
- **Check 3 shows Kali's IP (NAT), not .120**: you are likely on a bridge, not
  ipvlan. Confirm `docker network inspect hostonly_attackers` shows
  `"Driver": "ipvlan"` and `"ipvlan_mode": "l2"`.
- **IP collision**: `.120` must be free. Ensure the VirtualBox Host-Only **DHCP
  server is disabled** (or its pool excludes `.120–.135`) so nothing else grabs
  these addresses. The lab already uses static IPs, so DHCP is usually off.
- **macvlan alternative**: if ipvlan misbehaves, macvlan also works but then you
  MUST set the Kali Host-Only adapter's **Promiscuous Mode = Allow All** in
  VirtualBox (ipvlan L2 avoids this because all containers share Kali's MAC).

## Cleanup

```bash
docker network rm hostonly_attackers    # remove the test network when done
```

---

## Stage 1 — scale to four attackers (only after Stage 0 passes)

Planned next (not built yet): a `cyren-attacker` image (Debian-slim + sqlmap /
hydra / nmap / masscan / curl), a `docker-compose.yml` pinning four containers to
fixed IPs on `hostonly_attackers`, and `run_distributed.sh` to start them
staggered with per-tool rate limits (no DDoS):

| Container | IP | Tool | Attack |
|-----------|-----|------|--------|
| atk-sqlmap  | 192.168.56.120 | sqlmap | SQLi |
| atk-hydra   | 192.168.56.121 | hydra  | SSH brute |
| atk-nmap    | 192.168.56.122 | nmap   | Port scan |
| atk-masscan | 192.168.56.123 | masscan | Port scan (high-rate) |
