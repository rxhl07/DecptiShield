from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio_server import sio
import config 

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

@app.get("/")
async def root():
    # A simple health check to ensure our .env loaded properly
    db_status = "Loaded" if config.MONGO_URI else "Error: Missing MONGO_URI"
    return {
        "status": "DeceptiShield Backend is running successfully!",
        "database_config": db_status
    }