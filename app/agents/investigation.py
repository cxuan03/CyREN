"""
InvestigationAgent
==================
Role in the pipeline: the second agent. For an event that is not clearly low
risk, it (1) retrieves the most relevant MITRE ATT&CK techniques from ChromaDB
using GraphRAG, then (2) asks the configured LLM (local Ollama by default, Groq
as a fallback) to explain the event in natural language, grounded in those
retrieved techniques.

GraphRAG retrieval (`_graphrag_retrieve`): the query is embedded with Gemini
text-embedding-004 and vector-searched against the Gemini-embedded MITRE corpus
in ChromaDB, then expanded along the technique -> tactic -> sibling-technique
graph edge to surface related techniques a plain top-k would miss. If the
knowledge base is not built or Gemini is unreachable, it degrades to a static
rule -> technique map so the pipeline still runs (offline demos included).
Build/refresh the knowledge base with scripts/build_knowledge_base.py.

Output written to state:
    mitre_techniques : list[str]
    llm_summary      : {"what_happened", "what_could_go_wrong", "what_should_be_done"}
"""
import json
import logging

from config.settings import settings
from app.agents.state import AgentState

log = logging.getLogger(__name__)

# Import failures are recorded rather than swallowed: a broken dependency used
# to silently degrade every report to placeholder text with nothing in the logs
# to explain why.
try:
    from groq import Groq
    _GROQ_IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001 - report any cause
    Groq = None
    _GROQ_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

try:
    import chromadb
    _CHROMA_IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001
    chromadb = None
    _CHROMA_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


class InvestigationAgent:
    def __init__(self):
        self.provider = settings.LLM_PROVIDER
        self.groq = None
        self.llm_status = "not initialised"
        # the human-readable model name shown in reports / predictions
        self.model_name = (settings.OLLAMA_MODEL if self.provider == "ollama"
                           else settings.GROQ_MODEL)
        if self.provider == "ollama":
            self._init_ollama()
        else:
            self._init_groq()
        self.collection = None
        self._load_collection()

    def _init_groq(self):
        """Build the Groq client, explaining loudly if we cannot."""
        if Groq is None:
            self.llm_status = f"groq package unavailable ({_GROQ_IMPORT_ERROR})"
        elif not settings.GROQ_API_KEY:
            self.llm_status = "GROQ_API_KEY is not set in .env"
        else:
            try:
                self.groq = Groq(api_key=settings.GROQ_API_KEY)
                self.llm_status = f"ready (model {settings.GROQ_MODEL})"
                log.info("InvestigationAgent: Groq client %s", self.llm_status)
                return
            except Exception as exc:           # noqa: BLE001
                self.llm_status = f"Groq client failed to start: {type(exc).__name__}: {exc}"
        log.warning("InvestigationAgent: LLM analysis disabled - %s. "
                    "Reports will contain placeholder text.", self.llm_status)

    def _init_ollama(self):
        """Check the local Ollama server. Do not hard-fail: it may be started
        after the app, and a live call still works. The status explains what to
        do if the server is down or the model is not pulled yet."""
        import urllib.request
        try:
            with urllib.request.urlopen(
                    settings.OLLAMA_HOST.rstrip("/") + "/api/tags", timeout=3) as r:
                tags = json.loads(r.read().decode())
            names = [m.get("name", "") for m in tags.get("models", [])]
            base = settings.OLLAMA_MODEL.split(":")[0]
            if any(base in n for n in names):
                self.llm_status = f"ready (ollama {settings.OLLAMA_MODEL})"
                log.info("InvestigationAgent: Ollama %s", self.llm_status)
            else:
                self.llm_status = (f"ollama reachable but model {settings.OLLAMA_MODEL} "
                                   f"not pulled; run: ollama pull {settings.OLLAMA_MODEL}")
        except Exception as exc:               # noqa: BLE001
            self.llm_status = (f"ollama not reachable at {settings.OLLAMA_HOST} "
                               f"({type(exc).__name__}: {exc}); is 'ollama serve' running?")
        if not self.llm_status.startswith("ready"):
            log.warning("InvestigationAgent: LLM analysis disabled - %s.", self.llm_status)

    # ------------------------------------------------------------------
    def _chat_json(self, prompt: str, temperature: float, max_tokens: int):
        """Ask the configured provider for a strict-JSON reply.
        Returns (parsed_dict, error_str); exactly one is non-None."""
        if self.provider == "ollama":
            return self._ollama_json(prompt, temperature, max_tokens)
        return self._groq_json(prompt, temperature, max_tokens)

    def _groq_json(self, prompt, temperature, max_tokens):
        if self.groq is None:
            return None, self.llm_status
        try:
            resp = self.groq.chat.completions.create(
                model=settings.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature, max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
            return json.loads(resp.choices[0].message.content), None
        except Exception as exc:               # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    def _ollama_json(self, prompt, temperature, max_tokens):
        """Call the local Ollama server's chat API with JSON mode forced."""
        import urllib.request
        # keep_alive must be an int (seconds; -1 = forever) OR a duration string
        # like "30m". A numeric string ("-1") sent as-is is parsed by Ollama as a
        # bad duration and silently falls back to 5 min, so coerce it to int.
        ka = settings.OLLAMA_KEEP_ALIVE
        try:
            ka = int(ka)
        except (TypeError, ValueError):
            pass
        body = json.dumps({
            "model": settings.OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": "json",                  # Ollama JSON mode: valid JSON out
            "keep_alive": ka,                  # -1 => resident forever, no cold starts
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            settings.OLLAMA_HOST.rstrip("/") + "/api/chat",
            data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode())
            content = (data.get("message") or {}).get("content", "")
            return json.loads(content), None
        except Exception as exc:               # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------
    def chat_messages(self, messages, max_tokens: int = 600):
        """Free-text answer from the configured LLM given a full messages list
        (system + prior turns + current). Used by the SOC assistant chatbot, so
        multi-turn follow-ups work. Returns (text, error); one is non-None."""
        if self.provider == "ollama":
            return self._ollama_messages(messages, max_tokens)
        return self._groq_messages(messages, max_tokens)

    def chat_text(self, system: str, user: str, max_tokens: int = 600):
        """Single-turn convenience wrapper around chat_messages."""
        return self.chat_messages(
            [{"role": "system", "content": system},
             {"role": "user", "content": user}], max_tokens)

    def _ollama_messages(self, messages, max_tokens):
        import urllib.request
        ka = settings.OLLAMA_KEEP_ALIVE
        try:
            ka = int(ka)
        except (TypeError, ValueError):
            pass
        body = json.dumps({
            "model": settings.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "keep_alive": ka,
            "options": {"temperature": 0.2, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            settings.OLLAMA_HOST.rstrip("/") + "/api/chat",
            data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode())
            return (data.get("message") or {}).get("content", "").strip(), None
        except Exception as exc:               # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    def _groq_messages(self, messages, max_tokens):
        if self.groq is None:
            return None, self.llm_status
        try:
            resp = self.groq.chat.completions.create(
                model=settings.GROQ_MODEL, messages=messages,
                temperature=0.2, max_tokens=max_tokens,
            )
            return resp.choices[0].message.content.strip(), None
        except Exception as exc:               # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    def _load_collection(self):
        if chromadb is None:
            log.info("InvestigationAgent: chromadb unavailable (%s); using the static "
                     "MITRE fallback map.", _CHROMA_IMPORT_ERROR)
            return
        try:
            client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
            self.collection = client.get_collection(settings.CHROMA_COLLECTION)
        except Exception as exc:               # noqa: BLE001
            self.collection = None   # knowledge base not built yet
            log.info("InvestigationAgent: MITRE knowledge base not available (%s); "
                     "using the static fallback map.", exc)

    # ------------------------------------------------------------------
    # Static rule -> technique map (validated in the FYP1 prototype), used when
    # the ChromaDB knowledge base is not built or Gemini embeddings are
    # unreachable, so the pipeline still runs (offline demos included).
    _FALLBACK_MAP = {
        "SQL Injection": ["T1190 Exploit Public-Facing Application",
                          "T1213 Data from Information Repositories"],
        "SSH Brute Force": ["T1110.001 Brute Force: Password Guessing",
                            "T1078 Valid Accounts"],
        "Cross-Site Scripting": ["T1059.007 Command and Scripting Interpreter: JavaScript"],
        "Command Injection": ["T1059 Command and Scripting Interpreter"],
        "File Inclusion": ["T1005 Data from Local System"],
        "Port Scanning": ["T1046 Network Service Discovery"],
    }

    def _graphrag_retrieve(self, state: AgentState, k: int = 4) -> list:
        """GraphRAG retrieval over the MITRE ATT&CK knowledge base.

        1. Embed the event (attack_type + rule) with Gemini and vector-search
           ChromaDB for the k closest techniques.
        2. Expand along the technique -> tactic -> sibling-technique graph edge:
           pull the other techniques sharing a retrieved technique's tactic, so
           related context a plain top-k would miss is surfaced.

        Falls back to the static rule -> technique map if the knowledge base is
        not built or Gemini is unreachable.
        """
        if self.collection is None:
            return self._FALLBACK_MAP.get(state.get("attack_type", ""), [])

        try:
            from app.services import embeddings as emb
            query = f"{state.get('attack_type','')} {state.get('rule','')}".strip()
            qvec = emb.embed_query(query)
            res = self.collection.query(
                query_embeddings=[qvec], n_results=k,
                include=["metadatas"])
            metas = (res.get("metadatas") or [[]])[0]

            labels, tactics = [], []
            for m in metas:
                if not m:
                    continue
                if m.get("label") and m["label"] not in labels:
                    labels.append(m["label"])
                if m.get("tactic") and m["tactic"] not in tactics:
                    tactics.append(m["tactic"])

            # graph expansion: sibling techniques sharing a retrieved tactic
            for tac in tactics:
                sib = self.collection.get(
                    where={"tactic": tac}, include=["metadatas"])
                for m in sib.get("metadatas") or []:
                    if m and m.get("label") and m["label"] not in labels:
                        labels.append(m["label"])
            return labels
        except Exception as exc:               # noqa: BLE001 - never break pipeline
            log.warning("InvestigationAgent: GraphRAG retrieval failed (%s); "
                        "using the static fallback map.", exc)
            return self._FALLBACK_MAP.get(state.get("attack_type", ""), [])

    def _build_prompt(self, state: AgentState, techniques: list) -> str:
        """Compact prompt: only real context is included (empty enrichment
        fields are skipped) and the log sample is trimmed, to keep input
        tokens low. The model is asked to be brief to keep output tokens low."""
        lines = [
            "You are a SOC analyst assistant. Analyse this event and reply as "
            'strict JSON with keys "what_happened", "what_could_go_wrong", '
            '"what_should_be_done", "urgency" (IMMEDIATE|HIGH|MEDIUM|LOW). '
            "Keep each text field to 1-2 sentences.",
            "",
            f"Attack: {state.get('attack_type')} | rule: {state.get('rule')} | "
            f"source: {state.get('source_ip')} | logs: {state.get('log_count')}",
        ]
        if techniques:
            lines.append("MITRE: " + ", ".join(str(t) for t in techniques))

        # sample logs: at most 3, each truncated
        sample = [str(x)[:180] for x in (state.get("raw_logs") or [])[:3]]
        if sample:
            lines.append("Sample logs:\n" + "\n".join(sample))

        # enrichment: include only fields that actually carry information
        ti = state.get("threat_intel") or {}
        if ti.get("known_bad") or ti.get("score"):
            lines.append(f"Source reputation: known_bad={ti.get('known_bad')}, "
                         f"score={ti.get('score')}, sources={ti.get('sources')}")
        asset = state.get("asset") or {}
        if asset.get("name") or asset.get("criticality"):
            lines.append(f"Target asset: {asset.get('name')} "
                         f"(criticality {asset.get('criticality')})")
        vuln = state.get("vulnerability") or {}
        if vuln.get("matching_cves") or vuln.get("exploitable"):
            lines.append(f"Vulnerabilities: exploitable={vuln.get('exploitable')}, "
                         f"CVEs={vuln.get('matching_cves')}")
        return "\n".join(lines)

    @staticmethod
    def _placeholder(reason: str) -> dict:
        """Used only when the LLM is genuinely unavailable. The reason is
        carried into the summary so the report and the logs say why."""
        return {
            "what_happened": f"AI analysis unavailable: {reason}",
            "what_could_go_wrong": "",
            "what_should_be_done": "",
            "urgency": "MEDIUM",
            "llm_error": reason,
        }

    def _ask_llm(self, prompt: str) -> dict:
        # A failing LLM call must not take down the pipeline, but it must be
        # visible (carried into the report) rather than looking like empty analysis.
        out, err = self._chat_json(prompt, temperature=0.2,
                                   max_tokens=settings.GROQ_MAX_TOKENS)
        if err:
            log.error("InvestigationAgent: %s call failed - %s", self.provider, err)
            return self._placeholder(err)
        return out

    # ------------------------------------------------------------------
    def predict_next_stage(self, chain: dict) -> dict:
        """On-demand LLM deep prediction of an attack chain's next step, given
        the full chain context. Called by the "AI deep prediction" button, NOT
        in the pipeline, so it only spends a token when a user asks. Separate
        from the rule-based predicted_next (which stays as the fast baseline).
        Returns strict JSON; {"available": False, ...} if the LLM is off."""
        stages = chain.get("stages") or []
        lines = [
            "You are a senior SOC threat analyst. A single attacker produced the "
            "multi-stage attack chain below against one host. Predict the attacker's "
            "NEXT move based on the actual progression, not a generic template.",
            "",
            f"Source IP: {chain.get('source_ip')}",
            f"Highest risk so far: {chain.get('highest_risk')}",
            f"Rule-based baseline next stage: {chain.get('predicted_next')}",
            "",
            "Observed stages (kill-chain order):",
        ]
        for i, s in enumerate(stages, 1):
            mit = ", ".join(str(m) for m in (s.get("mitre") or []))
            lines.append(f"  {i}. {s.get('phase')} - {s.get('attack_type')}"
                         + (f" [{mit}]" if mit else "")
                         + f" @ {s.get('timestamp')}")
        lines += [
            "",
            "Rules for quality (follow ALL of them):",
            '- Every "why" MUST name at least one observed stage above by its attack '
            "type (e.g. 'after the SQL Injection at stage 2...') and explain the "
            "causal link from that stage to the predicted technique.",
            "- NEVER use filler like 'the attacker has demonstrated' or 'a high level "
            "of sophistication'. Be concrete about THIS chain.",
            "- The predictions must be three DIFFERENT techniques that each follow "
            "logically from the LAST observed stage; likelihoods roughly sum to 100.",
            '- "watch_for" must name concrete log sources or artefacts (e.g. auth logs, '
            "outbound connections, new files), not generic advice.",
            "",
            "Example of the expected specificity (for a DIFFERENT chain that ended in "
            "a web shell upload):",
            '{"next_techniques":[{"technique":"Credential Dumping","mitre":"T1003",'
            '"why":"The web shell from stage 3 gives command execution on the host, and '
            'the earlier SSH Brute Force shows the attacker wants reusable logins - '
            'dumping /etc/shadow is the natural next step.","likelihood":60}],'
            '"watch_for":"New processes spawned by the web server user and reads of '
            '/etc/shadow or SAM in the audit log.",'
            '"preemptive_action":"Quarantine the web root and rotate credentials used '
            'on this host.","confidence":"MEDIUM"}',
            "",
            "Reply as STRICT JSON with keys: "
            '"next_techniques" (array of 1-3 objects, each '
            '{"technique","mitre","why","likelihood"} where "likelihood" is an '
            'integer percentage 0-100 for how likely that technique is next; order '
            'the array from most to least likely), '
            '"watch_for" (what to watch for in logs/traffic, 1-2 sentences), '
            '"preemptive_action" (recommended action to take now, 1-2 sentences), '
            '"confidence" (HIGH|MEDIUM|LOW).',
        ]
        prompt = "\n".join(lines)
        out, err = self._chat_json(prompt, temperature=0.3,
                                   max_tokens=settings.GROQ_MAX_TOKENS)
        if err or out is None:
            reason = err or "empty response"
            log.error("InvestigationAgent: chain prediction failed - %s", reason)
            return {"available": False, "error": reason}
        out["available"] = True
        out["model"] = self.model_name
        return out

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        # low-risk events skip investigation to save LLM calls
        if state.get("risk") == "low":
            state["mitre_techniques"] = []
            state["llm_summary"] = {}
            return state

        techniques = self._graphrag_retrieve(state)
        prompt = self._build_prompt(state, techniques)
        summary = self._ask_llm(prompt)

        state["mitre_techniques"] = techniques
        state["llm_summary"] = summary
        return state


_investigation = InvestigationAgent()
def investigation_node(state: AgentState) -> AgentState:
    return _investigation.run(state)
