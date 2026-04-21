import os
from dotenv import load_dotenv

# Tell Python to look one folder up to find the .env file
load_dotenv(dotenv_path="../.env")

# Fetch all the variables
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "DeceptiShield")
OLLAMA_URL = os.getenv("OLLAMA_URL")
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", 2222))
HONEYTOKEN_USER = os.getenv("HONEYTOKEN_USER")
HONEYTOKEN_PASS = os.getenv("HONEYTOKEN_PASS")