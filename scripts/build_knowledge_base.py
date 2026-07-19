"""
Build the MITRE ATT&CK knowledge base in ChromaDB for the investigation agent.

    python scripts/build_knowledge_base.py

TODO (FYP2 implementation):
    1. Download the MITRE ATT&CK Enterprise data (STIX/JSON).
    2. For each technique, build a document (id, name, tactic, description).
    3. Embed with Gemini embeddings and add to the ChromaDB collection.

This stub shows the shape with two demo techniques.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings

try:
    import chromadb
except ImportError:
    print("Install chromadb first.")
    sys.exit(1)


def main():
    client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
    col = client.get_or_create_collection(settings.CHROMA_COLLECTION)

    # Seed corpus: the six techniques covered by the lab detection rules
    # (validated in the FYP1 prototype).
    # TODO (FYP2 increment): replace with the full MITRE ATT&CK Enterprise
    # STIX corpus and embed with Gemini embeddings.
    techniques = [
        {"id": "T1190", "text": "T1190 Exploit Public-Facing Application. Tactic: Initial "
                                "Access. Adversaries exploit a weakness in an internet-facing "
                                "host, such as SQL injection against a web application, to gain "
                                "access to the system or data."},
        {"id": "T1213", "text": "T1213 Data from Information Repositories. Tactic: Collection. "
                                "Adversaries leverage information repositories such as databases "
                                "to mine valuable information, often following SQL injection."},
        {"id": "T1059", "text": "T1059 Command and Scripting Interpreter. Tactic: Execution. "
                                "Adversaries abuse command interpreters (bash, sh, PowerShell) to "
                                "execute arbitrary commands, e.g. via command injection in a web "
                                "parameter."},
        {"id": "T1059.007", "text": "T1059.007 Command and Scripting Interpreter: JavaScript. "
                                "Tactic: Execution. Adversaries execute malicious JavaScript in a "
                                "victim's browser, the mechanism behind cross-site scripting "
                                "(XSS) attacks."},
        {"id": "T1005", "text": "T1005 Data from Local System. Tactic: Collection. Adversaries "
                                "read sensitive local files such as /etc/passwd, commonly via "
                                "local file inclusion (LFI) in a vulnerable web application."},
        {"id": "T1046", "text": "T1046 Network Service Discovery. Tactic: Discovery / "
                                "Reconnaissance. Adversaries enumerate services on remote hosts "
                                "with port scanners such as nmap to identify attack surface."},
        {"id": "T1110.001", "text": "T1110.001 Brute Force: Password Guessing. Tactic: "
                                "Credential Access. Adversaries repeatedly guess credentials for "
                                "services such as SSH, producing bursts of failed logins."},
        {"id": "T1078", "text": "T1078 Valid Accounts. Tactic: Defense Evasion / Persistence. "
                                "Adversaries use credentials obtained by brute force or theft to "
                                "log in as a legitimate user."},
    ]
    col.upsert(ids=[t["id"] for t in techniques], documents=[t["text"] for t in techniques])
    print(f"Upserted {len(techniques)} techniques into '{settings.CHROMA_COLLECTION}'.")
    print("TODO (FYP2 increment): load the full MITRE ATT&CK corpus and embed with Gemini.")


if __name__ == "__main__":
    main()
