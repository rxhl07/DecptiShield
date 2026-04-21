import socketio

# Create an async Socket.IO server. Allowing CORS '*' lets your React UI connect freely.
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

@sio.event
async def connect(sid, environ):
    print(f"[Socket.IO] Frontend Dashboard Connected! ID: {sid}")

@sio.event
async def disconnect(sid):
    print(f"[Socket.IO] Frontend Dashboard Disconnected. ID: {sid}")

# Our honeypot will call this function to broadcast live attacks to the UI
async def emit_new_command(session_id, command, ai_response, threat_score, severity):
    payload = {
        "sessionId": session_id,
        "command": command,
        "response": ai_response,
        "threatScore": threat_score,
        "severity": severity
    }
    await sio.emit('live_feed_update', payload)