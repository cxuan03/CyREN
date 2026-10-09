"""
Check that the LLM path used by the InvestigationAgent actually works.

    venv/Scripts/python.exe scripts/check_llm.py

Reports, in order, whether the groq package imports, whether the key is
loaded, which models the key can reach, whether the configured model is one
of them, and whether a real call returns usable JSON. Run this whenever a
report comes back with "AI analysis unavailable".
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings   # noqa: E402


def main_ollama():
    """Diagnostic for the local Ollama provider."""
    import urllib.request
    ok = True
    host = settings.OLLAMA_HOST.rstrip("/")
    print(f"provider: ollama  ({host}, model {settings.OLLAMA_MODEL})")

    print("1. server reachable")
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=5) as r:
            tags = json.loads(r.read().decode())
        names = [m.get("name", "") for m in tags.get("models", [])]
        print("   OK - models:", ", ".join(names) or "(none pulled)")
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        print("   fix: start Ollama (it serves on :11434), then re-run")
        return 1

    print(f"2. model {settings.OLLAMA_MODEL} pulled")
    base = settings.OLLAMA_MODEL.split(":")[0]
    if any(base in n for n in names):
        print("   OK")
    else:
        print(f"   FAILED - run: ollama pull {settings.OLLAMA_MODEL}")
        return 1

    print("3. live JSON call")
    try:
        body = json.dumps({
            "model": settings.OLLAMA_MODEL,
            "messages": [{"role": "user", "content": 'Reply with strict JSON: {"status":"ok"}'}],
            "stream": False, "format": "json",
            "keep_alive": settings.OLLAMA_KEEP_ALIVE,
        }).encode()
        req = urllib.request.Request(host + "/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode())
        out = json.loads((data.get("message") or {}).get("content", ""))
        print("   OK -", out)
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        ok = False

    print("\nRESULT:", "LLM analysis is working." if ok else "LLM analysis is NOT working.")
    return 0 if ok else 1


def main():
    if settings.LLM_PROVIDER == "ollama":
        return main_ollama()

    ok = True
    print("provider: groq")

    print("1. groq package")
    try:
        import groq
        print("   OK - version", getattr(groq, "__version__", "?"))
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        print("   fix: venv/Scripts/python.exe -m pip install --force-reinstall groq")
        return 1

    print("2. API key")
    key = settings.GROQ_API_KEY or ""
    if not key:
        print("   FAILED - GROQ_API_KEY is empty; set it in cyren/.env")
        return 1
    print(f"   OK - {key[:4]}... ({len(key)} chars)")

    print("3. client")
    try:
        client = groq.Groq(api_key=key)
        print("   OK")
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        return 1

    print("4. available models")
    try:
        names = sorted(m.id for m in client.models.list().data)
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        return 1
    for n in names:
        print("   -", n)

    print(f"5. configured model: {settings.GROQ_MODEL}")
    if settings.GROQ_MODEL not in names:
        print("   FAILED - not in the list above; update GROQ_MODEL in .env")
        ok = False
    else:
        print("   OK")

    print("6. live call")
    try:
        resp = client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user",
                       "content": 'Reply with strict JSON: {"status":"ok"}'}],
            temperature=0,
            response_format={"type": "json_object"},
        )
        data = json.loads(resp.choices[0].message.content)
        print("   OK -", data)
    except Exception as exc:
        print("   FAILED -", type(exc).__name__, exc)
        ok = False

    print("\nRESULT:", "LLM analysis is working." if ok else "LLM analysis is NOT working.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
