# CyREN

**Automating SOC Incident Response with Multi-Agent AI**

CyREN is an open-source multi-agent system that automates SOC incident response
for small and medium enterprises, as an affordable alternative to commercial
SOAR platforms. It reads alerts from an ELK Stack, triages them with an XGBoost
classifier, investigates them with an LLM grounded in the MITRE ATT&CK knowledge
base, reconstructs multi-stage attacks, and responds according to risk tier,
with a human-in-the-loop for uncertain cases.

---

## What is in this repository

The core pipeline is **implemented**: the validated FYP1 prototype logic
(Elasticsearch alert fetching, XGBoost triage, LLM investigation, kill-chain
correlation, iptables response) has been migrated into this architecture.
Remaining `TODO (FYP2 implementation)` markers cover the increments: the full
MITRE ATT&CK corpus with Gemini embeddings, GraphRAG traversal, and the
external threat-intel providers. The original prototype is archived in
`../legacy/` for reference.

```
cyren/
├── run.py                     # start the web app
├── requirements.txt
├── .env.example               # copy to .env and fill in
├── config/
│   └── settings.py            # reads all config from .env
├── app/
│   ├── __init__.py            # Flask app factory
│   ├── agents/
│   │   ├── state.py           # shared pipeline state
│   │   ├── triage.py          # TriageAgent (XGBoost)
│   │   ├── investigation.py   # InvestigationAgent (Groq + GraphRAG/ChromaDB)
│   │   ├── correlation.py     # CorrelationAgent (NetworkX)
│   │   ├── response.py        # ResponseAgent (iptables + email + report)
│   │   └── pipeline.py        # LangGraph orchestration
│   ├── api/
│   │   ├── routes.py          # REST API the dashboard calls
│   │   └── auth.py            # login / logout
│   ├── models/
│   │   └── db.py              # database schema
│   ├── services/
│   │   ├── siem_service.py    # reads + aggregates alerts from Elasticsearch
│   │   ├── event_service.py   # persists pipeline results (Event/Chain/Block/Report)
│   │   ├── scheduler.py       # background polling loop (replaces legacy backend.py)
│   │   ├── report_service.py  # PDF incident reports
│   │   └── email_service.py   # notification email
│   └── templates/
│       └── index.html         # the dashboard frontend
├── scripts/
│   ├── seed.py                # create demo users + data
│   ├── train_triage.py        # train the XGBoost model
│   └── build_knowledge_base.py# build the MITRE ATT&CK ChromaDB
└── tests/
    └── test_pipeline.py       # pipeline smoke tests
```

---

## Quick start (runs with placeholder logic, no API keys needed)

```bash
# 1. create a virtual environment
python -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate

# 2. install dependencies
pip install -r requirements.txt

# 3. configure
cp .env.example .env               # the defaults are fine for a first run

# 4. seed demo users and data
python scripts/seed.py

# 5. run
python run.py
```

Open <http://localhost:5000> and log in:

| Username    | Password        | Role    |
|-------------|-----------------|---------|
| `analyst01` | `Analyst@2026`  | Analyst |
| `manager01` | `Manager@2026`  | Manager |

At this point the dashboard is live and talking to the database. The four agents
run with fallback logic, so events route through the three tiers correctly even
before the real models are connected.

---

## Connecting the real components (FYP2)

Do these in any order. Each is independent; the app keeps working as you enable
them one at a time.

### 1. Elasticsearch (SIEM input) -- IMPLEMENTED

The query in `app/services/siem_service.py` targets the Kibana security alert
index (migrated from the validated FYP1 prototype). Just set
`ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD` and
`ELASTIC_ALERT_INDEX` in `.env`. Set `ENABLE_SCHEDULER=true` to poll and run
the pipeline automatically every `POLL_INTERVAL_SECONDS`.

### 2. XGBoost (triage) -- IMPLEMENTED

```bash
python scripts/train_triage.py     # trains + saves to data/models/triage_xgb.json
```

The script trains on the labelled attack / false-positive patterns from the
FYP1 lab (five features: rule, risk score, severity, payload keywords, log
volume), matching `app/agents/triage.py::_extract_features`. Once the model
file exists, `TriageAgent` loads it automatically; grow the dataset with the
Decision table labels as analysts approve / dismiss events.

> **Note on metrics:** report classification accuracy, not R². R² is a
> regression metric and does not apply to a classifier.

### 3. Groq + GraphRAG (investigation) -- LLM WIRED, GraphRAG PENDING

1. Put your `GROQ_API_KEY` in `.env` and the LLM analysis works end to end
   (grounded in a static rule -> MITRE technique map until the knowledge base
   is built).
2. Build the knowledge base (seeded with the six lab techniques):
   ```bash
   python scripts/build_knowledge_base.py
   ```
   FYP2 increment: load the full MITRE ATT&CK corpus and embed it with Gemini
   embeddings (`GEMINI_API_KEY`).
3. FYP2 increment: implement the GraphRAG traversal in
   `app/agents/investigation.py::_graphrag_retrieve` (currently plain vector
   search).

### 4. NetworkX (correlation) -- IMPLEMENTED

`CorrelationAgent` queries the `Event` table for earlier events from the same
source IP within the correlation window (default 180 days), orders them along
the kill chain, grades the chain (>=3 phases = CRITICAL), and predicts the
next stage. Chains are persisted to the `AttackChain` table.

### 5. iptables + email (response) -- IMPLEMENTED

On the **SIEM Server VM only**, set `ENABLE_IPTABLES=true` and configure the
`CYREN_BLOCK` chain. Blocks are idempotent (checked with `iptables -C` first)
and the dashboard unblock removes the rule again. Fill in the SMTP settings
for email notifications. Keep `ENABLE_IPTABLES=false` on your development
machine so it only simulates blocks.

### 6. Enrichment: threat intel, asset, vulnerability

These three add context that turns a raw classification into a prioritised
decision. They run **before** triage, so the risk tier already reflects them.

    danger = attack severity x asset criticality x exploitability x attacker reputation

**Threat Intelligence** (`app/enrichment/threat_intel.py`)
Dual-mode by design:
  - **Public IPs** query AbuseIPDB / VirusTotal / OTX. Put the keys in `.env`.
  - **Private IPs** (192.168.x / 10.x / 172.16-31.x) skip the external APIs,
    because those have no data on internal addresses and it wastes quota. They
    query the local feed instead: `data/threat_feed/blocklist.txt` plus an
    optional MISP instance. For the lab, add the internal IPs you want treated
    as known-bad to that file (the seed script pre-loads `.102` and `.107`).

**Asset Assessment** (`app/enrichment/asset_assessment.py`)
A simple asset inventory (IP -> name, criticality, owner, services). An attack
on a `critical` asset is escalated; an attack on a `low` spare box is not. This
is the capability SMEs most often lack. Populate it via the seed script or the
`/api/assets` endpoint.

**Vulnerability Assessment** (`app/enrichment/vuln_assessment.py`)
Holds the results of periodic scans (OpenVAS/Greenbone or `nmap --script
vulners`) keyed by IP. For each event it checks whether the target has a CVE
matching the attack type. Import scan results with:

    python scripts/import_vuln_scan.py <scan.xml>

**Enrichment API endpoints:**

| Method | Endpoint                     | Purpose                     |
|--------|------------------------------|-----------------------------|
| GET    | `/api/assets`                | Asset inventory             |
| GET    | `/api/vulnerabilities?ip=`   | Known vulnerabilities       |
| GET    | `/api/threat-intel/<ip>`     | Live reputation lookup      |

---

## The pipeline

```
ELK event (aggregated by source IP + rule)
        │
        ▼
   ┌─────────┐  low risk
   │ Triage  │ ──────────────┐
   │ XGBoost │               │
   └────┬────┘               │
        │ high | uncertain   │
        ▼                    │
 ┌───────────────┐           │
 │ Investigation │           │
 │ Groq+GraphRAG │           │
 └───────┬───────┘           │
         ▼                   │
   ┌─────────────┐           │
   │ Correlation │           │
   │  NetworkX   │           │
   └──────┬──────┘           │
          ▼                  ▼
      ┌──────────────────────────┐
      │        Response          │
      │  high      → block + email + report
      │  uncertain → human approval queue
      │  low       → log only
      └──────────────────────────┘
```

---

## API reference

All endpoints require a login session (cookie based).

| Method | Endpoint                        | Purpose                          |
|--------|---------------------------------|----------------------------------|
| POST   | `/api/login`                    | Log in                           |
| POST   | `/api/logout`                   | Log out                          |
| GET    | `/api/dashboard`                | Dashboard summary                |
| GET    | `/api/events`                   | List events (`?risk=&status=&ip=`)|
| GET    | `/api/events/<id>`              | Event detail                     |
| POST   | `/api/events/<id>/decision`     | Approve / dismiss                |
| GET    | `/api/chains`                   | Attack chains                    |
| GET    | `/api/chains/<id>`              | One chain                        |
| GET    | `/api/blocked`                  | Firewall blocks                  |
| POST   | `/api/blocked/<id>/unblock`     | Unblock an IP                    |
| GET    | `/api/reports`                  | Incident reports                 |
| GET    | `/api/users`                    | User management (manager only)   |
| POST   | `/api/ingest`                   | Run one event through the pipeline|

---

## Testing

```bash
python -m pytest
```

The smoke tests confirm that events route into the correct tier and that the
response actions match. They pass before the real models are connected, so you
can use them as a regression check as you build.

---

## Lab environment

Three VirtualBox VMs, matching the project design:

| VM            | OS             | Role                                          |
|---------------|----------------|-----------------------------------------------|
| SIEM Server   | Ubuntu 22.04   | Docker ELK stack, runs CyREN, iptables enabled|
| Target Server | Ubuntu         | Apache / MySQL / SSH / DVWA (the victim)      |
| Kali Linux    | Kali           | Attacker, IP aliases to simulate many sources |
