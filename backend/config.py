import os
from pathlib import Path
from dotenv import load_dotenv

# Look for .env next to this file first, then at the repo root. The old code
# used a CWD-relative "../.env", which only resolved if you happened to launch
# uvicorn from inside backend/ -- and silently loaded nothing otherwise.
_HERE = Path(__file__).resolve().parent
for _candidate in (_HERE / ".env", _HERE.parent / ".env"):
    if _candidate.is_file():
        load_dotenv(dotenv_path=_candidate)
        break

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "DeceptiShield")

# Full generate endpoint, not just the host, so it can point at a remote Ollama.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", 2222))
HONEYTOKEN_USER = os.getenv("HONEYTOKEN_USER")
HONEYTOKEN_PASS = os.getenv("HONEYTOKEN_PASS")
