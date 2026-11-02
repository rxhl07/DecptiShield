"""In-memory registry of attacker sessions (SSH honeypot + web simulator).

Every change emits a `session_update` event with the session summary so the
Sessions page can update live. Data is lost when the backend restarts.
"""

import datetime
from socketio_server import sio

MAX_LOGS_PER_SESSION = 500

sessions = {}


def _now_iso() -> str:
  return datetime.datetime.now(datetime.timezone.utc).strftime(
      "%Y-%m-%dT%H:%M:%SZ"
  )


def _summary(s: dict) -> dict:
  return {
      "sessionId": s["sessionId"],
      "ip": s["ip"],
      "source": s["source"],
      "startTime": s["startTime"],
      "endTime": s["endTime"],
      "status": s["status"],
      "threatScore": s["threatScore"],
      "commandCount": s["commandCount"],
  }


async def _emit(s: dict):
  try:
    await sio.emit("session_update", _summary(s))
  except Exception as e:
    print(f"[Session Registry] emit failed: {e}")


async def register_session(session_id: str, ip: str, source: str):
  if not session_id:
    return
  if session_id in sessions:
    return
  sessions[session_id] = {
      "sessionId": session_id,
      "ip": ip or "Unknown",
      "source": source,
      "startTime": _now_iso(),
      "endTime": None,
      "status": "active",
      "threatScore": 0,
      "commandCount": 0,
      "profile": None,
      "logs": [],
  }
  await _emit(sessions[session_id])


async def set_profile(session_id: str, profile: dict):
  s = sessions.get(session_id) if session_id else None
  if not s:
    return
  s["profile"] = profile
  await _emit(s)


async def record_command(
    session_id: str,
    command: str,
    severity: str,
    score: int,
    ip: str = None,
    response: str = None,
):
  if not session_id:
    return
  if session_id not in sessions:
    await register_session(session_id, ip, "UNKNOWN")
  s = sessions[session_id]
  s["commandCount"] += 1
  s["threatScore"] = score
  s["logs"].append({
      "id": f"{session_id}-{s['commandCount']}",
      "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
          "%Y-%m-%d %H:%M:%S"
      ),
      "command": command,
      "risk": severity,
      "score": score,
      "response": response,  # AI output shown to the attacker ("" = silent)
  })
  if len(s["logs"]) > MAX_LOGS_PER_SESSION:
    s["logs"] = s["logs"][-MAX_LOGS_PER_SESSION:]
  await _emit(s)


async def close_session(session_id: str):
  s = sessions.get(session_id) if session_id else None
  if not s or s["status"] == "closed":
    return
  s["status"] = "closed"
  s["endTime"] = _now_iso()
  await _emit(s)


def list_sessions() -> list:
  items = [_summary(s) for s in sessions.values()]
  items.sort(key=lambda x: x["startTime"], reverse=True)
  items.sort(key=lambda x: 0 if x["status"] == "active" else 1)
  return items


def get_session(session_id: str):
  s = sessions.get(session_id)
  if not s:
    return None
  detail = _summary(s)
  detail["profile"] = s["profile"]
  detail["logs"] = list(s["logs"])
  return detail
