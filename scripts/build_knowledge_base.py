"""
Build the MITRE ATT&CK knowledge base in ChromaDB for the InvestigationAgent's
GraphRAG retrieval.

    python scripts/build_knowledge_base.py

Each technique is embedded with Gemini text-embedding-004 and stored in ChromaDB
together with its tactic, so the InvestigationAgent can (1) vector-search for the
techniques closest to an event and (2) expand along the technique -> tactic ->
sibling-technique graph edge to pull in related context a plain top-k would miss.

The collection is rebuilt from scratch each run so the stored vectors are always
in the current Gemini embedding space (mixing embedding spaces breaks search).
The corpus is the set of techniques exercised by the lab detection rules; extend
TECHNIQUES to grow the knowledge base.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings

try:
    import chromadb
except ImportError:
    print("Install chromadb first:  pip install chromadb")
    sys.exit(1)

from app.services import embeddings as emb

# Corpus: the techniques covered by the lab detection rules. `label` is the short
# string surfaced in the UI/report; `text` is the richer document that gets
# embedded; `tactic` is the graph edge used for GraphRAG expansion.
TECHNIQUES = [
    {"id": "T1190", "tactic": "Initial Access",
     "label": "T1190 Exploit Public-Facing Application",
     "text": "T1190 Exploit Public-Facing Application. Tactic: Initial Access. "
             "Adversaries exploit a weakness in an internet-facing host, such as "
             "SQL injection against a web application, to gain access to the "
             "system or its data."},
    {"id": "T1213", "tactic": "Collection",
     "label": "T1213 Data from Information Repositories",
     "text": "T1213 Data from Information Repositories. Tactic: Collection. "
             "Adversaries leverage information repositories such as databases to "
             "mine valuable information, often following SQL injection."},
    {"id": "T1059", "tactic": "Execution",
     "label": "T1059 Command and Scripting Interpreter",
     "text": "T1059 Command and Scripting Interpreter. Tactic: Execution. "
             "Adversaries abuse command interpreters (bash, sh, PowerShell) to "
             "execute arbitrary commands, e.g. via command injection in a web "
             "parameter."},
    {"id": "T1059.007", "tactic": "Execution",
     "label": "T1059.007 Command and Scripting Interpreter: JavaScript",
     "text": "T1059.007 Command and Scripting Interpreter: JavaScript. Tactic: "
             "Execution. Adversaries execute malicious JavaScript in a victim's "
             "browser, the mechanism behind cross-site scripting (XSS) attacks."},
    {"id": "T1005", "tactic": "Collection",
     "label": "T1005 Data from Local System",
     "text": "T1005 Data from Local System. Tactic: Collection. Adversaries read "
             "sensitive local files such as /etc/passwd, commonly via local file "
             "inclusion (LFI) in a vulnerable web application."},
    {"id": "T1046", "tactic": "Discovery",
     "label": "T1046 Network Service Discovery",
     "text": "T1046 Network Service Discovery. Tactic: Discovery. Adversaries "
             "enumerate services on remote hosts with port scanners such as nmap "
             "to identify attack surface."},
    {"id": "T1110.001", "tactic": "Credential Access",
     "label": "T1110.001 Brute Force: Password Guessing",
     "text": "T1110.001 Brute Force: Password Guessing. Tactic: Credential "
             "Access. Adversaries repeatedly guess credentials for services such "
             "as SSH, producing bursts of failed logins."},
    {"id": "T1078", "tactic": "Defense Evasion",
     "label": "T1078 Valid Accounts",
     "text": "T1078 Valid Accounts. Tactic: Defense Evasion and Persistence. "
             "Adversaries use credentials obtained by brute force or theft to log "
             "in as a legitimate user."},
]


def main():
    if not emb.available():
        print("Gemini embeddings unavailable: set GEMINI_API_KEY in .env "
              "(and `pip install google-generativeai`). Aborting.")
        sys.exit(1)

    client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
    # Rebuild from scratch so every vector is in the current Gemini space.
    try:
        client.delete_collection(settings.CHROMA_COLLECTION)
    except Exception:                          # noqa: BLE001 - fine if absent
        pass
    col = client.create_collection(settings.CHROMA_COLLECTION)

    print(f"Embedding {len(TECHNIQUES)} techniques with Gemini "
          f"{settings.GEMINI_EMBED_MODEL} ...")
    vectors = [emb.embed_document(t["text"]) for t in TECHNIQUES]

    col.add(
        ids=[t["id"] for t in TECHNIQUES],
        documents=[t["text"] for t in TECHNIQUES],
        embeddings=vectors,
        metadatas=[{"tactic": t["tactic"], "label": t["label"]} for t in TECHNIQUES],
    )
    print(f"Upserted {len(TECHNIQUES)} techniques into "
          f"'{settings.CHROMA_COLLECTION}' at {settings.CHROMA_PERSIST_DIR} "
          f"(dim={len(vectors[0])}).")


if __name__ == "__main__":
    main()
