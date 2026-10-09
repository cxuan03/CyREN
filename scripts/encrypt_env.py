"""
Encrypt the project's .env into .env.enc so that credentials (API keys, the
Elasticsearch/SMTP passwords, the block-list token) are never stored in
plaintext in the repository or the submission.

How it works
------------
- The secret key is a Fernet key that lives ONLY in the CYREN_SECRET_KEY
  operating-system environment variable -- never in the repo.
- `.env`      : plaintext, git-ignored, used in local development.
- `.env.enc`  : the encrypted blob. Safe to commit / submit, because without
                CYREN_SECRET_KEY it is unreadable ciphertext.
- At startup `config/settings.py` decrypts `.env.enc` with CYREN_SECRET_KEY if
  both are present, otherwise it falls back to the plaintext `.env`.

Usage
-----
  # 1. Generate a key ONCE and keep it safe (outside the repo):
  python scripts/encrypt_env.py --genkey
  #    then set it as an environment variable:
  #      Windows : setx CYREN_SECRET_KEY "<the key>"
  #      bash    : export CYREN_SECRET_KEY="<the key>"
  #
  # 2. Encrypt (reads .env -> writes .env.enc):
  python scripts/encrypt_env.py
  #
  # 3. (optional) Verify it decrypts back:
  python scripts/encrypt_env.py --check
"""
import os
import sys

from cryptography.fernet import Fernet

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = os.path.join(ROOT, ".env")
ENC = os.path.join(ROOT, ".env.enc")


def _key() -> bytes:
    key = os.getenv("CYREN_SECRET_KEY")
    if not key:
        sys.exit(
            "CYREN_SECRET_KEY is not set.\n"
            "  Run:  python scripts/encrypt_env.py --genkey\n"
            "  Then set the printed value as the CYREN_SECRET_KEY env var and re-run."
        )
    return key.encode()


def main() -> None:
    args = sys.argv[1:]

    if "--genkey" in args:
        # A new Fernet key. Store it in CYREN_SECRET_KEY (OS env var, NOT the repo).
        print(Fernet.generate_key().decode())
        print("# ^ set this as CYREN_SECRET_KEY (keep it out of the repo)", file=sys.stderr)
        return

    if "--check" in args:
        if not os.path.exists(ENC):
            sys.exit(f"{ENC} not found -- run without --check to create it first.")
        plain = Fernet(_key()).decrypt(open(ENC, "rb").read()).decode("utf-8")
        n = sum(1 for ln in plain.splitlines() if "=" in ln and not ln.strip().startswith("#"))
        print(f"OK: {ENC} decrypts to {n} settings with the current CYREN_SECRET_KEY.")
        return

    # default: encrypt .env -> .env.enc
    if not os.path.exists(ENV):
        sys.exit(f"{ENV} not found -- nothing to encrypt.")
    token = Fernet(_key()).encrypt(open(ENV, "rb").read())
    with open(ENC, "wb") as fh:
        fh.write(token)
    print(
        f"Encrypted {ENV} -> {ENC} ({len(token)} bytes).\n"
        f"  .env.enc is safe to commit/submit (ciphertext).\n"
        f"  Keep .env and CYREN_SECRET_KEY OUT of the repo."
    )


if __name__ == "__main__":
    main()
