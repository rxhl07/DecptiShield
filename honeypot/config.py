import os
from pathlib import Path
from dotenv import load_dotenv

# Mirrors backend/config.py. Kept separate rather than imported because the two
# services build into separate containers. Look next to this file first, then
# at the repo root, then in backend/ (where the .env currently lives).
_HERE = Path(__file__).resolve().parent
for _candidate in (_HERE / ".env", _HERE.parent / ".env", _HERE.parent / "backend" / ".env"):
    if _candidate.is_file():
        load_dotenv(dotenv_path=_candidate)
        break

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "DeceptiShield")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", 2222))
