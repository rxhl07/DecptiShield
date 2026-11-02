import os
from pathlib import Path
from dotenv import load_dotenv

# Look for .env next to this file first, then at the repo root, so it loads
# from wherever the backend is started.
_HERE = Path(__file__).resolve().parent
for _candidate in (_HERE / ".env", _HERE.parent / ".env"):
  if _candidate.is_file():
    load_dotenv(dotenv_path=_candidate)
    break

# Fetch all the variables
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "DeceptiShield")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", 2222))
HONEYTOKEN_USER = os.getenv("HONEYTOKEN_USER")
HONEYTOKEN_PASS = os.getenv("HONEYTOKEN_PASS")
