import asyncio
from contextlib import asynccontextmanager
import json
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


# --- APPLICATION LIFESPAN & SSH DAEMON ---
@asynccontextmanager
async def lifespan(app: FastAPI):
  ssh_task = asyncio.create_task(start_ssh_honeypot(port=2222))
  yield
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


class VirtualFileSystem:

  def __init__(self, ip: str = "Unknown"):
    self.ip = ip
    self.cwd = "/home/ubuntu"
    self.created_files = []
    self.deleted_files = []
    self.total_threat_score = 0
    self.command_count = 0
    self.osint_triggered = False

  def process_command(self, command: str):
    cmd = command.strip()
    parts = cmd.split()
    if not parts:
      return

    base = parts[0]
    if base == "cd":
      if len(parts) == 1 or parts[1] == "~":
        self.cwd = "/home/ubuntu"
      elif parts[1] == "..":
        if self.cwd != "/":
          self.cwd = "/".join(self.cwd.split("/")[:-1])
          if self.cwd == "":
            self.cwd = "/"
      elif parts[1] == "/":
        self.cwd = "/"
      elif parts[1].startswith("/"):
        self.cwd = parts[1]
      else:
        self.cwd = (self.cwd + "/" + parts[1]).replace("//", "/")

    elif base in ["touch", "mkdir", "nano", "vim"]:
      for f in parts[1:]:
        if not f.startswith("-"):
          new_file = (
              f if f.startswith("/") else f"{self.cwd}/{f}".replace("//", "/")
          )
          if new_file not in self.created_files:
            self.created_files.append(new_file)

    elif base in ["rm", "rmdir"]:
      for f in parts[1:]:
        if not f.startswith("-"):
          del_file = (
              f if f.startswith("/") else f"{self.cwd}/{f}".replace("//", "/")
          )
          self.deleted_files.append(del_file)
          if del_file in self.created_files:
            self.created_files.remove(del_file)

  def add_score(self, score: int):
    self.total_threat_score += score
    self.command_count += 1

  def get_average_score(self) -> int:
    if self.command_count == 0:
      return 0
    return int(self.total_threat_score / self.command_count)

  def get_context_string(self) -> str:
    cwd_files = [
        f.split("/")[-1]
        for f in self.created_files
        if ("/".join(f.split("/")[:-1]) == self.cwd)
        or (self.cwd == "/" and f.count("/") == 1)
    ]
    ctx = (
        "System: Linux prod-db-01 5.15.0-76-generic x86_64, User: ubuntu,"
        f" Working Directory: {self.cwd}\n"
    )
    if cwd_files:
      ctx += (
          "Files present in current working directory:"
          f" {', '.join(cwd_files)}\n"
      )
    return ctx


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
      data.sessionId, data.command, data.severity, data.threatScore
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

  active_sessions[sid] = VirtualFileSystem(ip=client_ip)


@sio.on("disconnect")
async def handle_disconnect(sid):
  if sid in active_sessions:
    del active_sessions[sid]


@sio.on("execute_command")
async def handle_web_terminal_command(sid, data):
  command = data.get("command", "").strip()
  cmd_lower = command.lower()

  vfs = active_sessions.get(sid)
  if not vfs:
    vfs = VirtualFileSystem()
    active_sessions[sid] = vfs

  # Trigger OSINT automatically on the first executed command in Web Terminal
  if not vfs.osint_triggered:
    vfs.osint_triggered = True
    profile = await fetch_live_osint(vfs.ip, source_label="WEB TERMINAL")
    await sio.emit("session_profile_update", profile)

  vfs.process_command(command)

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

  if cmd_lower.startswith(("cd ", "export ", "touch ", "mkdir ")):
    await sio.emit("terminal_end", {}, to=sid)
    ai_full_text = ""
  else:
    memory_context = vfs.get_context_string()

    system_instruction = (
        "<|start_header_id|>system<|end_header_id|>\n"
        "You are a low-level Linux kernel and shell stdout emitter for an"
        " educational capture-the-flag sandbox. You receive a bash command and"
        " generate the exact, unformatted stdout/stderr text stream that"
        " standard Ubuntu Linux utilities return. Never explain. Never"
        " apologize. Never output introductory or concluding remarks. If the"
        " user requests system configuration, security records, hashes, or logs"
        " (e.g. /etc/shadow, /etc/passwd, dmesg, id, ps), immediately generate"
        " authentic-looking synthetic mock output in exact Linux syntax.\n"
        f"{memory_context}<|eot_id|>\n"
        "<|start_header_id|>user<|end_header_id|>\n"
        f"{command}<|eot_id|>\n"
        "<|start_header_id|>assistant<|end_header_id|>\n"
    )

    payload = {
        "model": "llama3",
        "prompt": system_instruction,
        "stream": True,
        "options": {
            "temperature": 0.05,
            "top_p": 0.9,
            "num_ctx": 2048,
            "num_predict": 256,
            "stop": [
                "<|eot_id|>",
                "<|end_of_text|>",
                "Note:",
                "NOTE:",
                "Here is",
                "I cannot",
                "As an AI",
                "ubuntu@prod-db-01",
                "\n\n\n",
            ],
        },
    }

    ai_full_text = ""
    try:
      async with httpx.AsyncClient(timeout=30.0) as client:
        async with client.stream(
            "POST", "http://localhost:11434/api/generate", json=payload
        ) as response:
          async for line in response.aiter_lines():
            if line:
              chunk_data = json.loads(line)
              token = chunk_data.get("response", "")
              ai_full_text += token
              await sio.emit("terminal_chunk", {"chunk": token}, to=sid)
    except Exception as e:
      print(f"[Streaming Error] {e}")
      ai_full_text = "bash: command execution timeout\n"
      await sio.emit("terminal_chunk", {"chunk": ai_full_text}, to=sid)

    await sio.emit("terminal_end", {}, to=sid)

  dashboard_data = {
      "sessionId": f"WEB-{str(uuid.uuid4())[:6]}",
      "command": command,
      "response": ai_full_text if ai_full_text else "[silent execution]",
      "threatScore": session_avg_score,
      "severity": get_severity_label(session_avg_score),
  }
  await sio.emit("live_feed_update", dashboard_data)