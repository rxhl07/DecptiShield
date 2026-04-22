from pymongo import MongoClient
import datetime
import uuid
import sys
import os

# Import our config
# Note: Since this is in the honeypot folder, we'll manually load the .env 
# to ensure we get that MONGO_URI
from dotenv import load_dotenv
load_dotenv(dotenv_path="../.env")

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "deceptishield")

class DBWriter:
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_URI)
            self.db = self.client[DB_NAME]
            self.sessions = self.db["sessions"]
            self.events = self.db["events"]
            print("[DB] Successfully connected to MongoDB Atlas")
        except Exception as e:
            print(f"[DB Error] Connection failed: {e}")

    def create_session(self, attacker_ip, city, country):
        """Initializes a new session record when an attacker logs in."""
        session_id = str(uuid.uuid4())
        session_doc = {
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "location": f"{city}, {country}",
            "start_time": datetime.datetime.utcnow(),
            "event_count": 0,
            "max_threat_score": 0,
            "is_active": True
        }
        self.sessions.insert_one(session_doc)
        return session_id

    def log_event(self, session_id, command, response, score, severity):
        """Logs every command and AI response into the events collection."""
        event_doc = {
            "session_id": session_id,
            "timestamp": datetime.datetime.utcnow(),
            "command": command,
            "response": response,
            "threat_score": score,
            "severity": severity
        }
        self.events.insert_one(event_doc)
        
        # Update the parent session's summary stats
        self.sessions.update_one(
            {"session_id": session_id},
            {
                "$inc": {"event_count": 1},
                "$max": {"max_threat_score": score}
            }
        )
        print(f"[DB] Logged event for session {session_id[:8]}: {command}")

# Singleton instance
db_writer = DBWriter()