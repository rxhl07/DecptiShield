import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys
import uuid
import config
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel
import socketio
from socketio_server import sio
from ssh_honeypot import start_ssh_honeypot
import session_registry

# The command engine lives at the repo root, shared with the SSH honeypot.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import llm_client
from shared import command_engine
from shared.command_engine import VirtualFileSystem


# --- APPLICATION LIFESPAN & SSH DAEMON ---
@asynccontextmanager
async def lifespan(app: FastAPI):
  ssh_task = asyncio.create_task(start_ssh_honeypot(port=2222))
  preload_task = asyncio.create_task(llm_client.preload())
  yield
  preload_task.cancel()
  ssh_task.cancel()


app = FastAPI(title="DeceptiShield API", version="1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

latest_profile = {
    "ip": "127.0.0.1",
    "geo": "Waiting for Attacker...",
    "isp": "Local Loopback",
    "org": "Internal Network",
    "type": "IDLE / LISTENING",
}


class TelemetryData(BaseModel):
  sessionId: str
  command: str
  response: str
  threatScore: int
  severity: str


class AttackerProfileRequest(BaseModel):
  ip: str
  source: str = "SSH"
  sessionId: Optional[str] = None


class WebSession(VirtualFileSystem):
  """Engine state plus the web terminal's own connection details."""

  def __init__(self, ip: str = "Unknown"):
    super().__init__()
    self.ip = ip
    self.osint_triggered = False
    # Stable id for this web-terminal socket; registered on first command
    self.session_id = f"WEB-{str(uuid.uuid4())[:6]}"
    self.registered = False


active_sessions = {}


def get_severity_label(score: int) -> str:
  if score >= 80:
    return "CRITICAL"
  if score >= 55:
    return "HIGH"
  if score >= 30:
    return "MEDIUM"
  return "LOW"


async def fetch_live_osint(
    ip: str,
    source_label: str = "LIVE INCOMING",
    override_public_ip: str = None,
):
  global latest_profile
  lookup_ip = override_public_ip if override_public_ip else ip
  is_internal = False

  # Check if incoming connection is pure local loopback or local subnet
  if lookup_ip in ["127.0.0.1", "::1", "localhost"]:
    is_internal = True
    profile = {
        "ip": f"{ip} (Host Loopback)",
        "geo": "Local Interface / Tunnel Endpoint",
        "isp": "ngrok TCP Tunnel / Localhost",
        "org": "Internal Ingress",
        "type": f"{source_label} INTERCEPT",
    }
    latest_profile = profile
    return profile

  if lookup_ip.startswith("192.168.") or lookup_ip.startswith("10."):
    is_internal = True
    profile = {
        "ip": f"{ip} (LAN Node)",
        "geo": "Local Area Network",
        "isp": "Internal Subnet Router",
        "org": "Intranet Attacker Machine",
        "type": f"{source_label} (LAN)",
    }
    latest_profile = profile
    return profile

  # Remote WAN IP Lookup via ip-api.com
  try:
    async with httpx.AsyncClient(timeout=5.0) as client:
      response = await client.get(f"http://ip-api.com/json/{lookup_ip}")
      data = response.json()
      if data.get("status") == "success":
        profile = {
            "ip": lookup_ip,
            "geo": f"{data.get('city')}, {data.get('country')}",
            "isp": data.get("isp", "Unknown ISP"),
            "org": data.get("org", "Unknown Org"),
            "type": f"{source_label} WAN INTERCEPT",
        }
        latest_profile = profile
        return profile
  except Exception as e:
    print(f"[OSINT Query Failed] {e}")

  profile = {
      "ip": lookup_ip,
      "geo": "Undetermined Location",
      "isp": "External Provider",
      "org": "Remote Node",
      "type": f"{source_label} INTERCEPT",
  }
  latest_profile = profile
  return profile


@app.get("/")
async def root():
  db_status = (
      "Loaded"
      if getattr(config, "MONGO_URI", None)
      else "Error: Missing MONGO_URI"
  )
  return {
      "status": "DeceptiShield Backend is running successfully!",
      "database_config": db_status,
      "socket_io": "Active",
  }


@app.get("/api/profile")
async def get_current_profile():
  return latest_profile


@app.get("/api/sessions")
async def get_sessions():
  return session_registry.list_sessions()


@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
  detail = session_registry.get_session(session_id)
  if detail is None:
    raise HTTPException(status_code=404, detail="Session not found")
  return detail


@app.post("/internal/attacker-connected")
async def register_attacker(data: AttackerProfileRequest):
  profile = await fetch_live_osint(
      data.ip, source_label=f"{data.source} INGRESS"
  )
  if data.sessionId:
    profile = {**profile, "sessionId": data.sessionId}
    await session_registry.set_profile(data.sessionId, profile)
  await sio.emit("session_profile_update", profile)
  return {"status": "profile_updated", "profile": profile}


@app.post("/internal/emit")
async def receive_honeypot_data(data: TelemetryData):
  await session_registry.record_command(
      data.sessionId,
      data.command,
      data.severity,
      data.threatScore,
      response=data.response,
  )
  await sio.emit(
      "live_feed_update",
      data.model_dump() if hasattr(data, "model_dump") else data.dict(),
  )
  return {"status": "broadcast_complete"}


# --- SOCKET EVENTS ---


@sio.on("connect")
async def handle_connect(sid, environ):
  client_ip = environ.get(
      "HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "127.0.0.1")
  )
  if "," in client_ip:
    client_ip = client_ip.split(",")[0].strip()

  active_sessions[sid] = WebSession(ip=client_ip)


@sio.on("disconnect")
async def handle_disconnect(sid):
  if sid in active_sessions:
    vfs = active_sessions[sid]
    if getattr(vfs, "registered", False):
      await session_registry.close_session(vfs.session_id)
    del active_sessions[sid]


async def announce_web_attacker(ip: str, session_id: str):
  """Background OSINT lookup for a web-terminal attacker, tagged with its session.

  Runs as a task so the first command is not held up by the lookup. If the
  session has closed by the time this finishes, set_profile still saves it
  quietly (closed sessions stay listed) or skips it if the id is unknown.
  """
  try:
    profile = await fetch_live_osint(ip, source_label="WEB TERMINAL")
    profile = {**profile, "sessionId": session_id}
    await session_registry.set_profile(session_id, profile)
    await sio.emit("session_profile_update", profile)
  except Exception as e:
    print(f"[OSINT Error] Web attacker lookup failed for {session_id} ({ip}): {e}")


@sio.on("execute_command")
async def handle_web_terminal_command(sid, data):
  command = data.get("command", "").strip()
  cmd_lower = command.lower()

  vfs = active_sessions.get(sid)
  if not vfs:
    vfs = WebSession()
    active_sessions[sid] = vfs

  # Trigger OSINT automatically on the first executed command in Web Terminal
  if not vfs.registered:
    vfs.registered = True
    await session_registry.register_session(vfs.session_id, vfs.ip, "WEB")

  if not vfs.osint_triggered:
    vfs.osint_triggered = True
    asyncio.create_task(announce_web_attacker(vfs.ip, vfs.session_id))

  vfs.record(command)

  current_cmd_score = 10
  if any(
      x in cmd_lower
      for x in [
          "sudo",
          "rm",
          "wget",
          "curl",
          "chmod",
          "chown",
          "shadow",
          "nmap",
          "sudoers",
      ]
  ):
    current_cmd_score = 90
  elif any(
      x in cmd_lower
      for x in ["cat", "ls", "cd", "find", "grep", "netstat", "ps", "passwd"]
  ):
    current_cmd_score = 40

  vfs.add_score(current_cmd_score)
  session_avg_score = vfs.get_average_score()

  # Tiered dispatch: the model only sees commands that need invented output.
  result = command_engine.handle_command(command, vfs)
  if result.intel:
    print(f"[INTEL] {sid}: {result.intel}")

  ai_full_text = result.output
  if not result.needs_llm:
    if ai_full_text:
      await sio.emit("terminal_chunk", {"chunk": ai_full_text + "\n"}, to=sid)
  else:
    lines = []
    async for line in llm_client.stream_reply(command, vfs):
      lines.append(line)
      await sio.emit("terminal_chunk", {"chunk": line + "\n"}, to=sid)
    ai_full_text = "\n".join(lines)

  await sio.emit("terminal_end", {}, to=sid)

  dashboard_data = {
      "sessionId": vfs.session_id,
      "command": command,
      "response": ai_full_text if ai_full_text else "[silent execution]",
      "threatScore": session_avg_score,
      "severity": get_severity_label(session_avg_score),
  }
  await session_registry.record_command(
      vfs.session_id,
      command,
      dashboard_data["severity"],
      session_avg_score,
      ip=vfs.ip,
      response=ai_full_text,
  )
  await sio.emit("live_feed_update", dashboard_data)