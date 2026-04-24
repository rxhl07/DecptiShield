from fastapi import FastAPI, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio_server import sio
import config 
from pydantic import BaseModel
import httpx
import uuid

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

# ---------------------------------------------------------
# VIRTUAL FILE SYSTEM (VFS) STATE MANAGER
# ---------------------------------------------------------
class VirtualFileSystem:
    def __init__(self):
        self.cwd = "/home/ubuntu"
        self.created_files = []
        self.deleted_files = []
        self.total_threat_score = 0
        self.command_count = 0

    def process_command(self, command):
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
                self.cwd = self.cwd + "/" + parts[1] if self.cwd != "/" else "/" + parts[1]
                
        elif base in ["touch", "mkdir", "nano", "vim"]:
            for f in parts[1:]:
                if not f.startswith("-"):
                    new_file = f"{self.cwd}/{f}".replace("//", "/")
                    if new_file not in self.created_files:
                        self.created_files.append(new_file)
                        
        elif base in ["rm", "rmdir"]:
            for f in parts[1:]:
                if not f.startswith("-"):
                    del_file = f"{self.cwd}/{f}".replace("//", "/")
                    self.deleted_files.append(del_file)
                    if del_file in self.created_files:
                        self.created_files.remove(del_file)

    def add_score(self, score):
        self.total_threat_score += score
        self.command_count += 1

    def get_average_score(self):
        if self.command_count == 0:
            return 0
        return int(self.total_threat_score / self.command_count)

    def get_context_string(self):
        ctx = f"Current Working Directory: {self.cwd}\n"
        if self.created_files:
            ctx += f"Files created by user: {', '.join(self.created_files)}\n"
        if self.deleted_files:
            ctx += f"Files deleted by user: {', '.join(self.deleted_files)}\n"
        return ctx

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

@sio.on('execute_command')
async def handle_web_terminal_command(sid, data):
    command = data.get("command", "").strip()
    cmd_lower = command.lower()
    
    vfs = active_sessions.get(sid)
    if not vfs:
        vfs = VirtualFileSystem()
        active_sessions[sid] = vfs
        
    vfs.process_command(command)
    
    current_cmd_score = 10
    if any(x in cmd_lower for x in ["sudo", "rm", "wget", "curl", "chmod", "chown"]):
        current_cmd_score = 90
    elif any(x in cmd_lower for x in ["cat", "ls", "cd", "find", "grep"]):
        current_cmd_score = 40
    
    vfs.add_score(current_cmd_score)
    session_avg_score = vfs.get_average_score()

    instant_responses = {
        "whoami": "ubuntu",
        "pwd": vfs.cwd,
        "id": "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo)",
        "uname -a": "Linux prod-db-01 5.15.0-76-generic #83-Ubuntu SMP Wed Jun 21 20:23:31 UTC 2023 x86_64 GNU/Linux",
        "uname": "Linux",
        "hostname": "prod-db-01",
        "date": "Fri Apr 24 11:30:50 UTC 2026",
    }

    ai_text = ""
    
    if cmd_lower.startswith("cd "):
        ai_text = ""
        await sio.emit('terminal_response', {'output': "\r\n"}, to=sid)
    elif cmd_lower in instant_responses:
        ai_text = instant_responses[cmd_lower] + "\r\n"
        await sio.emit('terminal_response', {'output': ai_text}, to=sid)
    else:
        memory_context = vfs.get_context_string()
        payload = {
            "model": "llama3", 
            "prompt": f"You are a vulnerable Ubuntu Linux server. {memory_context}\nThe user typed: {command}. Respond with ONLY the exact terminal output. Do not explain anything. If the command lists files (like ls), YOU MUST include the 'Files created by user' in your output, and DO NOT display 'Files deleted by user'.",
            "stream": False
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post("http://localhost:11434/api/generate", json=payload)
                ai_text = response.json().get("response", "bash: command not found")
                await sio.emit('terminal_response', {'output': ai_text}, to=sid)
        except Exception as e:
            ai_text = "bash: connection to host failed\r\n"
            await sio.emit('terminal_response', {'output': ai_text}, to=sid)

    dashboard_data = {
        "sessionId": f"WEB-{str(uuid.uuid4())[:6]}",
        "command": command,
        "response": ai_text,
        "threatScore": session_avg_score,
        "severity": get_severity_label(session_avg_score)
    }

    await sio.emit('live_feed_update', dashboard_data)