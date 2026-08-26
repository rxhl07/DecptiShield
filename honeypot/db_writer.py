from pymongo import MongoClient
import datetime
import uuid

import config

MONGO_URI = config.MONGO_URI
DB_NAME = config.DB_NAME


class DBWriter:
    def __init__(self):
        self.client = None
        try:
            if not MONGO_URI:
                raise ValueError("MONGO_URI is not set -- check your .env")
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            # pymongo connects lazily, so without this ping a bad URI still
            # printed "Successfully connected" and only failed later on insert.
            self.client.admin.command("ping")
            self.db = self.client[DB_NAME]
            self.sessions = self.db["sessions"]
            self.events = self.db["events"]
            print(f"[DB] Connected to MongoDB, database '{DB_NAME}'")
        except Exception as e:
            self.client = None
            print(f"[DB Error] Connection failed: {e}")
            print("[DB] Continuing without persistence -- the live feed still works.")

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
        if self.client:
            try:
                self.sessions.insert_one(session_doc)
            except Exception as e:
                print(f"[DB Error] create_session: {e}")
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
        if not self.client:
            return

        try:
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
        except Exception as e:
            print(f"[DB Error] log_event: {e}")

# Singleton instance
db_writer = DBWriter()