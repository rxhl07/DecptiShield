from fastapi import FastAPI, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio_server import sio
import config 
from pydantic import BaseModel

# Initialize the FastAPI app
app = FastAPI(title="DeceptiShield API", version="1.0 (MVP)")

# Allow the frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Combine FastAPI and Socket.IO into one app
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

# Data model for incoming honeypot events
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
    """
    Receives real data from the honeypot and pushes to Frontend.
    """
    print(f"[Backend] Broadcasting command: {data.command}")
    await sio.emit('live_feed_update', data.dict())
    return {"status": "broadcast_complete"}

@app.get("/test-trigger")
async def trigger_test_event():
    """
    NUCLEAR OPTION: Manually fire an event to see if the 
    Dashboard updates without needing an SSH connection.
    """
    test_data = {
        "sessionId": "test-123",
        "command": "rm -rf /",
        "response": "Permission denied: You are not root.",
        "threatScore": 95,
        "severity": "CRITICAL"
    }
    await sio.emit('live_feed_update', test_data)
    return {"message": "Test event fired to frontend!"}