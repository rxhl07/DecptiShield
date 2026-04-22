import httpx

# This points to the FastAPI backend we built earlier
BACKEND_URL = "http://localhost:8000/internal/emit"

async def emit_to_backend(session_id, command, response, score, severity):
    """
    Sends data to the FastAPI backend, which then broadcasts it via Socket.IO
    """
    payload = {
        "sessionId": session_id,
        "command": command,
        "response": response,
        "threatScore": score,
        "severity": severity
    }
    
    try:
        async with httpx.AsyncClient() as client:
            # We will add this endpoint to our FastAPI main.py next
            await client.post(BACKEND_URL, json=payload)
    except Exception as e:
        print(f"[Emitter Error] Could not reach backend: {e}")