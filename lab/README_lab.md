# CyREN lab — traffic generation

Drive six attacks against the lab DVWA target with **industry-standard tools**
(sqlmap, hydra, nmap, curl) so the ELK detection rules fire on genuine attack
traffic, **and** generate matching **benign** user traffic so the classifier
has negative samples. Replaces the hand-written `auto_attack.sh`.

> Authorised use only. Everything here targets your own isolated Host-Only lab
> (`192.168.56.0/24`). `attack_dvwa.sh` refuses any non-private target.

## Files

| File | Runs on | Purpose |
|------|---------|---------|
| `attack_dvwa.sh` | Kali (attacker) | Sends the six attacks from three aliased source IPs |
| `benign_traffic.sh` | Kali / any host | Generates **normal** user traffic from a benign IP (negative samples) |
| `target_setup.sh` | Target Server (DVWA) | Adds the iptables `PORTSCAN` log so scans leave a trace |

## Attacker IP aliasing (kept from your design)

`attack_dvwa.sh` adds three aliases to the Kali interface and routes each
attack out of one of them, so CyREN sees multiple sources and can build
attack chains:

| Source IP | Attacks | Tool |
|-----------|---------|------|
| `192.168.56.104` | SQL Injection, File Inclusion | sqlmap, curl |
| `192.168.56.150` | XSS, Command Injection | curl |
| `192.168.56.151` | SSH Brute Force, Port Scan | hydra, nmap |

A single `ip route replace <target> src <alias>` per phase controls the source
address for **every** tool (sqlmap, hydra and `nmap -sT` all use the OS socket
stack), so no per-tool source-bind flags are needed.

## Deployment

### 1. Target Server (once)

```bash
scp lab/target_setup.sh user@192.168.56.101:/tmp/
ssh user@192.168.56.101 'sudo bash /tmp/target_setup.sh'
```

Confirm Filebeat ships `/var/log/kern.log` (or `/var/log/syslog`) and
`/var/log/auth.log` (for SSH) and `/var/log/apache2/access.log` (for the web
attacks). The system + apache Filebeat modules cover these:

```bash
sudo filebeat modules enable system apache
sudo systemctl restart filebeat
```

### 2. Kali (attacker)

```bash
sudo apt install -y sqlmap hydra nmap curl     # if not already present
sudo IFACE=eth0 TARGET=192.168.56.101 ./attack_dvwa.sh
```

Run one attack at a time while tuning rules:

```bash
sudo ./attack_dvwa.sh --only ssh
sudo ./attack_dvwa.sh --only scan
```

### 3. Verify

- Kibana → Security → Alerts: you should see all six rule names.
- CyREN dashboard: new events for the three source IPs.
- `venv/Scripts/python.exe scripts/backfill_events.py --hours 24 --dry-run`
  on the CyREN host lists what will be ingested.

## Detection-rule queries (match real tool traffic)

Set these as the KQL query for each rule in Kibana → Security → Rules. They
match the **URL path** (always logged verbatim, never URL-encoded) or a
reliable keyword, so real sqlmap/curl traffic trips them every time:

| Rule | Type | Query |
|------|------|-------|
| SQL Injection Detected | query | `host.name: "target-server" and message: "vulnerabilities/sqli"` |
| XSS Attack Detected | query | `host.name: "target-server" and message: "vulnerabilities/xss_r"` |
| Command Injection Detected | query | `host.name: "target-server" and message: "vulnerabilities/exec"` |
| File Inclusion Detected | query | `host.name: "target-server" and message: "vulnerabilities/fi"` |
| SSH Brute Force Detected | threshold (host.name ≥ 5) | `host.name: "target-server" and message: "Failed password"` |
| Port Scan Detected | query | `host.name: "target-server" and message: "PORTSCAN"` |

Why path-based instead of `UNION SELECT` / `script`: Apache logs the request
line URL-encoded, so `UNION SELECT` appears as `UNION%20SELECT` and the
standard analyzer tokenises `%20` apart — a `match_phrase "UNION SELECT"`
misses it. The `vulnerabilities/sqli` path is always present in cleartext, and
because the traffic is genuine sqlmap injection (not a page visit), matching
the path is now an honest detection.

Rules use `from: now-90s`, so they only alert on **new** logs — re-run the
attack after any rule change to generate fresh alerts.

## Benign traffic — negative samples (`benign_traffic.sh`)

A classifier that only ever sees attacks cannot tell a true positive from a
false positive. `benign_traffic.sh` generates **normal user activity** from a
dedicated benign IP so the training set has non-threat samples:

```bash
sudo IFACE=eth0 TARGET=192.168.56.101 ./benign_traffic.sh
# add a normal SSH login (needs a real account on the target + sshpass):
sudo SSH_USER=labuser SSH_PASS=Labpass123 ./benign_traffic.sh --only ssh
```

All of it comes from **`192.168.56.160`** (change with `BENIGN_IP=`), separate
from the three attacker IPs, so benign events are trivial to filter and label.

It produces three kinds of benign traffic:

| Kind | Example | In ELK |
|------|---------|--------|
| Baseline browsing | `index.php`, `about.php`, CSS/JS/images, normal login | Normal logs, **no alert** |
| Legitimate use of the demo pages | `sqli/?id=1`, `xss_r/?name=John`, `exec` ping `127.0.0.1`, `fi/?page=include.php` | Trips the path rule → **false-positive alert** |
| Normal SSH | correct password login, runs `whoami; uptime` | `Accepted password` (not `Failed`) → **no brute alert** |

The middle row is the important one: it visits the **same URL paths** an
attacker uses, but with harmless inputs (`id=1`, `name=John`, no shell
metacharacters) and at a **human pace** (1–4 s think-time, low request count).
The path-based rule flags it, yet the triage features that matter — no attack
keyword/payload, low `request_count` — are the opposite of a real attack. These
are exactly the false positives the classifier must learn to dismiss.

### Building the labelled training set

1. Run `attack_dvwa.sh` (positives) and `benign_traffic.sh` (negatives).
2. In CyREN, events from `.104/.150/.151` are **true positives**; events from
   `.160` are **benign / false positives**. Dismissing the `.160` events in the
   Human Approval queue records them as `false_positive` in the `Decision`
   table, which feeds continuous learning; or label by source IP when exporting
   a training set for `scripts/train_triage.py`.
3. Re-run both scripts over several sessions to build volume and variety.

## Notes for the write-up

- **Benign vs malicious, same surface:** the negative samples deliberately hit
  the same DVWA endpoints as the attacks but without payloads and at a normal
  rate, so the paper's claim — "the dataset contains both real threats and
  benign activity to distinguish true from false positives" — is backed by data
  that actually exercises that distinction, not by traffic to unrelated pages.

- Real tools = real payloads: sqlmap performs actual boolean/error/UNION
  injection; hydra performs a real credential brute force; nmap performs a
  real TCP connect scan. This is defensible as "attacks simulated with
  industry-standard tooling (sqlmap, hydra, nmap)".
- The three source IPs let you demonstrate multi-source triage and, because
  `.104` runs two stages (SQLi then FI), the correlation agent's attack-chain
  logic on real data.
