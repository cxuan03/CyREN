# CyREN

**Automating SOC Incident Response with Multi-Agent AI**

CyREN is a multi-agent system that automates Security Operations Centre (SOC)
incident response for small and medium enterprises, as an affordable
alternative to commercial SOAR platforms. It reads alerts from an ELK Stack,
triages them with an XGBoost classifier, investigates them with a local LLM
grounded in a MITRE ATT&CK knowledge base, reconstructs multi-stage attack
chains, opens case tickets, and responds according to risk tier, keeping a
human in the loop for uncertain cases.

Final Year Project, INTI International University, 2026.

---

## How it works

```
Target VM (DVWA)  --Filebeat-->  Logstash  -->  Elasticsearch  <--poll every 5 s--  CyREN scheduler
                                                                                        |
                                             +------------------------------------------+
                                             v
                      enrich -> triage (XGBoost) -> investigate (LLM) -> correlate -> respond
                                                                                        |
                       high      -> add to blocklist + alert email + ticket             |
                       uncertain -> human approval queue + ticket                       |
                       low       -> log only                                            |
                                             |
   Target VM pulls /api/blocklist every 10 s and applies it with ipset  <----------------+
```

1. **Collect.** Filebeat on the target VM ships Apache, auth and kernel logs
   into the ELK stack (Docker). `siem_service.py` aggregates matching raw logs
   into one *event* per `(source IP, detection rule)`.
2. **Poll.** A background scheduler inside the Flask process asks
   Elasticsearch for new activity every `POLL_INTERVAL_SECONDS` and skips
   events that have not changed since the last run.
3. **Pipeline.** Each new event runs through five agents orchestrated with
   LangGraph (`app/agents/pipeline.py`):
   - **Enrich** – asset criticality, known vulnerabilities, local threat feed.
   - **Triage** – XGBoost classifier assigns `high` / `low` / `uncertain`
     using the `HIGH_RISK_THRESHOLD` / `LOW_RISK_THRESHOLD` cut-offs
     (defaults 0.85 / 0.40, tunable by a manager in Settings).
   - **Investigate** – a local LLM served by Ollama explains why the event is
     suspicious, grounded in the MITRE ATT&CK knowledge base (ChromaDB).
     Low-risk events skip this step.
   - **Correlate** – links earlier events from the same source into an attack
     chain ordered along the kill chain (NetworkX) with MITRE technique tags.
   - **Respond** – acts on the risk tier according to the configured
     automation level (`advisory`, `standard`, `full_auto`).
4. **Tickets.** After each cycle the scheduler auto-raises a case ticket for
   every new chain or actionable source (`ticket_service.auto_raise`).
5. **Contain.** CyREN only *publishes* a blocklist (`GET /api/blocklist`,
   token-protected). The target VM runs the agent in `deploy/target-agent/`,
   which pulls the list every 10 seconds and enforces it locally with
   **ipset** plus a single iptables DROP rule. A whitelist on the target
   guarantees the host and the target itself are never blocked, and the last
   good list stays in force if the network drops.

---

## Features

| Area | What you get |
|------|--------------|
| Dashboard | Live counters, risk breakdown, recent activity, approval queue |
| All Events | Filterable table, event detail with deterministic "why this is an attack" evidence, MITRE badges, LLM explanation |
| Raw Logs | Read-only live viewer over Elasticsearch with one-click escalation to an event |
| Attack Chains | Reconstructed multi-stage attacks with timeline |
| Case Tickets | Queue / board / month timeline, assignment, comments with @mentions, activity log, PDF dossier |
| Team Chat | Direct messages and groups with attachments, replies, forwarding, read markers |
| Reports | Per-event archive plus a Report Builder (date range, pick chains / tickets / events, PDF or CSV) |
| Assets & Whitelist | IP-keyed asset inventory with criticality; never-block whitelist |
| Audit Log | Every analyst / manager action, including logins |
| Security | Admin-provisioned accounts, password policy, two-step verification (security question), emailed one-time code for password reset, idle auto-logout, login lockout, 7 granular permissions, Fernet-encrypted `.env` |

---

## Repository layout

```
cyren/
├── run.py                        # start the web app (scheduler runs inside)
├── requirements.txt
├── .env.example                  # copy to .env and fill in
├── config/settings.py            # every setting, read from .env
├── app/
│   ├── agents/                   # enrich / triage / investigation / correlation / response + LangGraph pipeline
│   ├── enrichment/               # asset, vulnerability and threat-intel lookups
│   ├── api/                      # routes.py (REST API) and auth.py (login, 2-step, password reset)
│   ├── models/db.py              # SQLAlchemy schema
│   ├── services/                 # siem, scheduler, event, ticket, chat, report, email, embeddings, attack_evidence
│   ├── static/                   # logo and images
│   └── templates/                # single-page dashboard (index.html), login, register
├── scripts/                      # train_triage, build_knowledge_base, export_training_set, seed, migrations, encrypt_env …
├── deploy/target-agent/          # ipset blocklist agent installed on the target VM (+ INSTALL.md)
├── lab/                          # attack / benign traffic generators and dataset collector (run on Kali)
├── notebooks/, report_notebooks/ # classifier comparison and system evaluation (automation rate, MTTD, MTTR)
└── tests/                        # pytest: pipeline routing and agent behaviour
```

---

## Quick start (development machine)

Requirements: Python 3.11, a reachable Elasticsearch, and
[Ollama](https://ollama.com) with a chat model pulled.

```bash
python -m venv venv
venv\Scripts\activate              # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

copy .env.example .env             # then edit .env (see "Configuration")
python scripts/seed.py             # demo users and lab assets
python run.py
```

Open <http://localhost:5000>.

`scripts/seed.py` creates two demo accounts (`manager01`, `analyst01`); their
passwords are in the script. Change them before any real deployment. New users
are provisioned by a manager from the User Management page; self-registration
is disabled.

### Configuration

All settings live in `.env` (never committed). The important ones:

| Setting | Purpose |
|---------|---------|
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD` | ELK connection |
| `ENABLE_SCHEDULER`, `POLL_INTERVAL_SECONDS` | automatic polling (set `true` / `5` for the lab) |
| `HIGH_RISK_THRESHOLD`, `LOW_RISK_THRESHOLD` | triage routing cut-offs |
| `LLM_PROVIDER=ollama`, `OLLAMA_HOST`, `OLLAMA_MODEL` | local LLM for the investigation agent |
| `GEMINI_API_KEY`, `GEMINI_EMBED_MODEL` | embeddings used to build the MITRE ATT&CK ChromaDB |
| `BLOCKLIST_TOKEN` | shared secret the target agent presents to `/api/blocklist` |
| `SMTP_*`, `ALERT_EMAIL_TO` | alert and notification email (optional) |
| `ENABLE_IPTABLES` | legacy direct-iptables mode; keep `false` (blocking is done by the target agent) |

**Secrets at rest.** `python scripts/encrypt_env.py` encrypts `.env` into
`.env.enc` with a Fernet key held in the `CYREN_SECRET_KEY` OS environment
variable; on start-up CyREN decrypts it in memory and falls back to a plain
`.env` if the key is absent. Neither file is ever committed.

### Train the triage model and build the knowledge base

```bash
python scripts/export_training_set.py --label-manifest lab/dataset_manifest.csv
python scripts/train_triage.py             # -> data/models/triage_xgb.json
python scripts/build_knowledge_base.py     # -> data/chroma (MITRE ATT&CK)
```

`source_ip` is used only to *label* the training rows and is never a feature,
so the model learns behaviour rather than memorising addresses.

### Tests

```bash
python -m pytest
```

---

## Lab environment

Everything runs on one Windows machine with VirtualBox. The VMs share an
isolated host-only network `192.168.56.0/24` with no route to the internet.

| Where | Address | Runs |
|-------|---------|------|
| Windows host | `192.168.56.1` | CyREN (`run.py`, port 5000), ELK via Docker Desktop (`docker-elk`: Elasticsearch 9200, Logstash 5044, Kibana 5601), Ollama (11434) |
| Target-Server VM (Ubuntu) | `192.168.56.101` | DVWA, SSH, Filebeat, the `deploy/target-agent` ipset blocklist sync |
| Kali-Attacker VM | aliases `.104 / .150 / .151` plus Docker ipvlan containers | traffic generators in `lab/` |

Six attack classes are generated with standard tools so the Kibana detection
rules fire on genuine traffic: SQL injection and file inclusion (sqlmap, curl),
XSS and command injection (curl), SSH brute force (Hydra, Medusa) and port
scanning (Nmap, Masscan). `lab/benign_traffic.sh` produces normal browsing
from a separate IP so the classifier also learns what *not* to flag, and
`lab/collect_dataset.sh` records labelled, intensity-randomised sessions for
training. See `lab/README_lab.md` and `deploy/target-agent/INSTALL.md`.

> The lab scripts refuse any non-private target address. Use them only on
> infrastructure you own and are authorised to test.

---

## API overview

All endpoints need a login session. Main groups under `/api`:

`login`, `login-verify`, `logout`, `forgot-password`, `reset-password` ·
`dashboard` · `events` · `raw-logs` · `chains` · `cases` (tickets) · `chat` ·
`notifications` · `blocked`, `whitelist`, `blocklist` (feed for the target
agent) · `reports`, `report-notes`, `export` · `assets`, `vulnerabilities`,
`threat-intel` · `users`, `capabilities`, `settings`, `model`, `audit`, `me`.

---

## Evaluation

`report_notebooks/objective4_system_evaluation.ipynb` computes automation
rate, false-positive identification rate (benign recall), mean time to
detect (from the Kibana alert index) and mean time to respond (detection to
block) from the live database; `notebooks/objective3_classifier_comparison.ipynb`
compares XGBoost with Random Forest, Logistic Regression and SVM on the
labelled grey-zone dataset.
