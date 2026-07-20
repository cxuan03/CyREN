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


def main():
    ok = True

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
