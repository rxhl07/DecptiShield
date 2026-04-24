from fastapi import FastAPI, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio_server import sio
import config 
from pydantic import BaseModel
import httpx
import uuid # For generating session IDs for web users

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
    print(f"[Backend] Broadcasting command from SSH: {data.command}")
    await sio.emit('live_feed_update', data.dict())
    return {"status": "broadcast_complete"}

# --- WEB TERMINAL LISTENER --- 
@sio.on('execute_command')
async def handle_web_terminal_command(sid, data):
    command = data.get("command", "")
    print(f"[Web Terminal] Received command: {command}")
    
    payload = {
        "model": "llama3", 
        "prompt": f"You are a vulnerable Linux server. The user typed: {command}. Respond with ONLY the exact terminal output. No explanations.",
        "stream": False
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post("http://localhost:11434/api/generate", json=payload)
            ai_text = response.json().get("response", "bash: command not found")
            
            # 1. Send the response BACK to the terminal UI
            await sio.emit('terminal_response', {'output': ai_text}, to=sid)
            
            # --- THE MISSING FIX: Update the Dashboard ---
            # Basic threat logic for the web terminal simulation
            cmd_lower = command.lower()
            score = 10
            severity = "LOW"
            
            if any(x in cmd_lower for x in ["sudo", "rm", "wget", "curl"]):
                score = 90
                severity = "CRITICAL"
            elif any(x in cmd_lower for x in ["cat", "ls", "cd"]):
                score = 40
                severity = "MEDIUM"

            dashboard_data = {
                "sessionId": f"WEB-{str(uuid.uuid4())[:6]}",
                "command": command,
                "response": ai_text,
                "threatScore": score,
                "severity": severity
            }

            # 2. Broadcast to the Live Feed (This makes the dashboard light up!)
            await sio.emit('live_feed_update', dashboard_data)
            print(f"[Backend] Web command broadcasted to dashboard: {command}")
            
    except Exception as e:
        print(f"[Web Terminal Error] AI unreachable: {e}")
        await sio.emit('terminal_response', {'output': 'bash: connection to host failed\r\n'}, to=sid)