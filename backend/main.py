from fastapi import FastAPI, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio_server import sio
import config
from pydantic import BaseModel
import httpx
import uuid
import sys
from pathlib import Path

# The command engine lives at the repo root so the SSH honeypot can import the
# same module -- both entry points must agree on how commands behave.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import command_engine
from shared.command_engine import VirtualFileSystem

# Initialize the FastAPI app
app = FastAPI(title="DeceptiShield API", version="1.0 (MVP)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

class TelemetryData(BaseModel):
    sessionId: str
    command: str
    response: str
    threatScore: int
    severity: str

# VirtualFileSystem now lives in shared/command_engine.py so the SSH honeypot
# shares the same session state model.

active_sessions = {}

def get_severity_label(score):
    if score >= 80: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

# --- NEW: OSINT PROFILING MODULE ---
async def get_osint_data(ip):
    """Queries external database for geolocation and ISP data."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "geo": f"{data.get('city')}, {data.get('country')}",
                    "isp": data.get("isp"),
                    "org": data.get("org")
                }
    except Exception as e:
        print(f"[OSINT Error] Could not query database: {e}")
    return None

@app.get("/")
async def root():
    db_status = "Loaded" if config.MONGO_URI else "Error: Missing MONGO_URI"
    return {
        "status": "DeceptiShield Backend is running successfully!",
        "database_config": db_status,
        "socket_io": "Active"
    }

@app.post("/internal/emit")
async def receive_honeypot_data(data: TelemetryData):
    await sio.emit('live_feed_update', data.dict())
    return {"status": "broadcast_complete"}


@app.post("/internal/session_start")
async def receive_session_start(data: dict = Body(...)):
    """
    A real SSH session opened on the honeypot. Enrich the IP and push it to the
    dashboard's attacker-profile card -- the SSH path previously never sent
    this, so that panel only ever populated from the browser terminal.
    """
    ip = data.get("ip")
    enriched = await get_osint_data(ip)
    if enriched:
        data["geo"] = enriched["geo"]
        data["isp"] = enriched["isp"]
        data["org"] = enriched["org"]
    else:
        data.setdefault("geo", "UNKNOWN LOCATION")
        data.setdefault("isp", "UNKNOWN ISP")

    print(f"[OSINT] SSH session from {ip}: {data.get('geo')} via {data.get('isp')}")
    await sio.emit('session_profile_update', data)
    return {"status": "profile_broadcast"}

@sio.on('connect')
async def handle_connect(sid, environ):
    active_sessions[sid] = VirtualFileSystem()

@sio.on('disconnect')
async def handle_disconnect(sid):
    if sid in active_sessions:
        del active_sessions[sid]

@sio.on('session_start')
async def handle_session_start(sid, data):
    initial_ip = data.get('ip')
    print(f"[Backend] Routing {initial_ip} to OSINT Module for unmasking...")
    
    # Perform OSINT Query
    enriched_profile = await get_osint_data(initial_ip)
    
    # Merge API data with frontend data
    if enriched_profile:
        data['geo'] = enriched_profile['geo']
        data['isp'] = enriched_profile['isp']
        data['org'] = enriched_profile['org']
    else:
        data['geo'] = "UNKNOWN LOCATION"
        data['isp'] = "UNKNOWN ISP"
        
    print(f"[OSINT] Profile Unmasked: {data.get('geo')} via {data.get('isp')}")
    await sio.emit('session_profile_update', data)

def _to_terminal(text):
    """
    xterm needs CRLF line endings. No trailing newline and empty stays empty --
    the client decides line breaks, otherwise silent commands produce blank
    lines instead of nothing.
    """
    if not text:
        return ""
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


# Reused across requests so we don't pay a new TCP+TLS handshake per command.
_llm_client = None


def _get_llm_client():
    global _llm_client
    if _llm_client is None:
        _llm_client = httpx.AsyncClient(timeout=60.0)
    return _llm_client


@sio.on('execute_command')
async def handle_web_terminal_command(sid, data):
    command = data.get("command", "").strip()
    cmd_lower = command.lower()
    
    vfs = active_sessions.get(sid)
    if not vfs:
        vfs = VirtualFileSystem()
        active_sessions[sid] = vfs
        
    vfs.record(command)

    current_cmd_score = 10
    if any(x in cmd_lower for x in ["sudo", "rm", "wget", "curl", "chmod", "chown"]):
        current_cmd_score = 90
    elif any(x in cmd_lower for x in ["cat", "ls", "cd", "find", "grep"]):
        current_cmd_score = 40

    vfs.add_score(current_cmd_score)
    session_avg_score = vfs.get_average_score()

    # Tiered dispatch. The engine updates VFS state itself and only hands back
    # needs_llm for commands that genuinely require invention -- roughly one in
    # twenty in practice, so most commands answer in well under a millisecond.
    result = command_engine.handle_command(command, vfs)

    if result.intel:
        print(f"[INTEL] {sid}: {result.intel}")

    if not result.needs_llm:
        ai_text = result.output
        await sio.emit('terminal_response',
                       {'output': _to_terminal(ai_text), 'cwd': vfs.cwd}, to=sid)
    else:
        payload = {
            "model": config.OLLAMA_MODEL,
            "messages": command_engine.build_messages(command, vfs),
            "stream": False,
            "keep_alive": -1,
            "options": {"num_predict": 256, "temperature": 0.4},
        }
        try:
            response = await _get_llm_client().post(
                command_engine.chat_url(config.OLLAMA_URL), json=payload)
            ai_text = response.json().get("message", {}).get("content", "")
            ai_text = command_engine.sanitize_llm_output(ai_text)
            # Reject output that contradicts state we know to be true, or that
            # came back empty because the model broke character.
            validated = command_engine.validate_against_state(ai_text, command, vfs)
            if validated is None:
                print(f"[Validation] rejected model output for: {command}")
                ai_text = command_engine.fallback_output(command)
            else:
                ai_text = validated
                # Remember it, so asking again gives the same answer.
                command_engine.remember_llm_output(command, ai_text, vfs)
            await sio.emit('terminal_response',
                           {'output': _to_terminal(ai_text), 'cwd': vfs.cwd}, to=sid)
        except Exception as e:
            # Degrade to a plausible shell rather than showing an error string.
            print(f"[AI Error] {e}")
            ai_text = command_engine.fallback_output(command)
            await sio.emit('terminal_response',
                       {'output': _to_terminal(ai_text), 'cwd': vfs.cwd}, to=sid)

    dashboard_data = {
        "sessionId": f"WEB-{str(uuid.uuid4())[:6]}",
        "command": command,
        "response": ai_text,
        "threatScore": session_avg_score,
        "severity": get_severity_label(session_avg_score)
    }

    await sio.emit('live_feed_update', dashboard_data)