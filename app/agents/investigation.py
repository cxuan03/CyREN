"""
InvestigationAgent
==================
Role in the pipeline: the second agent. For an event that is not clearly low
risk, it (1) retrieves the most relevant MITRE ATT&CK techniques from ChromaDB
using GraphRAG, then (2) asks Llama 4 Scout (via Groq) to explain the event in
natural language, grounded in those retrieved techniques.

Output written to state:
    mitre_techniques : list[str]
    llm_summary      : {"what_happened", "what_could_go_wrong", "what_should_be_done"}

TODO (FYP2 implementation):
    1. Build the ChromaDB knowledge base with scripts/build_knowledge_base.py
       (embed the MITRE ATT&CK corpus with Gemini embeddings).
    2. Implement the graph traversal in `_graphrag_retrieve` (your GraphRAG
       logic over the technique/tactic graph). The stub below does a plain
       vector similarity search as a fallback.
    3. Tune the prompt in `_build_prompt`.
"""
import json

from config.settings import settings
from app.agents.state import AgentState

try:
    from groq import Groq
except ImportError:
    Groq = None

try:
    import chromadb
except ImportError:
    chromadb = None


class InvestigationAgent:
    def __init__(self):
        self.groq = Groq(api_key=settings.GROQ_API_KEY) if (Groq and settings.GROQ_API_KEY) else None
        self.collection = None
        self._load_collection()

    def _load_collection(self):
        if chromadb is None:
            return
        try:
            client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
            self.collection = client.get_collection(settings.CHROMA_COLLECTION)
        except Exception:
            self.collection = None   # knowledge base not built yet

    # ------------------------------------------------------------------
    def _graphrag_retrieve(self, state: AgentState, k: int = 5) -> list:
        """
        TODO: real GraphRAG retrieval.
        Retrieve techniques related to this event, then expand along the
        technique -> tactic -> related-technique graph edges to gather context
        that a plain vector search would miss.

        The stub below does a plain similarity query as a fallback so the
        pipeline runs before GraphRAG is implemented.
        """
        if self.collection is None:
            # Fallback: static rule -> technique map validated in the FYP1
            # prototype, used until the ChromaDB knowledge base is built.
            fallback = {
                "SQL Injection": ["T1190 Exploit Public-Facing Application",
                                  "T1213 Data from Information Repositories"],
                "SSH Brute Force": ["T1110.001 Brute Force: Password Guessing",
                                    "T1078 Valid Accounts"],
                "Cross-Site Scripting": ["T1059.007 Command and Scripting Interpreter: JavaScript"],
                "Command Injection": ["T1059 Command and Scripting Interpreter"],
                "File Inclusion": ["T1005 Data from Local System"],
                "Port Scanning": ["T1046 Network Service Discovery"],
            }
            return fallback.get(state.get("attack_type", ""), [])

        query = f"{state.get('attack_type','')} {state.get('rule','')}"
        res = self.collection.query(query_texts=[query], n_results=k)
        docs = res.get("documents", [[]])[0]
        return docs

    def _build_prompt(self, state: AgentState, techniques: list) -> str:
        ti = state.get("threat_intel", {})
        asset = state.get("asset", {})
        vuln = state.get("vulnerability", {})
        return (
            "You are a SOC analyst assistant. Analyse the security event below "
            "using the provided context. Give particular weight to whether the "
            "target is a critical asset and whether it has a matching unpatched "
            "vulnerability, because those decide how urgent this is. Respond as "
            'strict JSON with keys "what_happened", "what_could_go_wrong", '
            '"what_should_be_done", and "urgency" (one of IMMEDIATE, HIGH, '
            "MEDIUM, LOW).\n\n"
            f"Event:\n"
            f"- Source IP: {state.get('source_ip')}\n"
            f"- Attack type: {state.get('attack_type')}\n"
            f"- Rule: {state.get('rule')}\n"
            f"- Log count: {state.get('log_count')}\n"
            f"- Sample logs: {json.dumps(state.get('raw_logs', [])[:5])}\n\n"
            f"MITRE ATT&CK context:\n{json.dumps(techniques)}\n\n"
            f"Threat intelligence on the source:\n"
            f"- Scope: {ti.get('scope')}, known bad: {ti.get('known_bad')}, "
            f"score: {ti.get('score')}, sources: {ti.get('sources')}\n\n"
            f"Target asset:\n"
            f"- Name: {asset.get('name')}, criticality: {asset.get('criticality')}, "
            f"owner: {asset.get('owner')}, services: {asset.get('services')}\n\n"
            f"Target vulnerabilities:\n"
            f"- Exploitable by this attack: {vuln.get('exploitable')}, "
            f"matching CVEs: {vuln.get('matching_cves')}, "
            f"total known: {vuln.get('vuln_count')}\n"
        )

    def _ask_llm(self, prompt: str) -> dict:
        if self.groq is None:
            # PLACEHOLDER analysis so the pipeline runs without a Groq key
            return {
                "what_happened": "Placeholder analysis. Connect the Groq API to generate this.",
                "what_could_go_wrong": "Placeholder risk assessment.",
                "what_should_be_done": "Placeholder recommendation.",
                "urgency": "MEDIUM",
            }
        resp = self.groq.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        try:
            return json.loads(resp.choices[0].message.content)
        except (json.JSONDecodeError, AttributeError, IndexError):
            return {"what_happened": resp.choices[0].message.content,
                    "what_could_go_wrong": "", "what_should_be_done": "",
                    "urgency": "MEDIUM"}

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
