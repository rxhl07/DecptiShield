import httpx

import config

# The honeypot is a separate process with no browser connection of its own, so
# it hands events to the backend over HTTP and the backend broadcasts them to
# every connected dashboard via Socket.IO.
EMIT_URL = f"{config.BACKEND_URL}/internal/emit"
SESSION_START_URL = f"{config.BACKEND_URL}/internal/session_start"


async def emit_to_backend(session_id, command, response, score, severity):
    """Push one executed command to the dashboard's live feed."""
    payload = {
        "sessionId": session_id,
        "command": command,
        "response": response,
        "threatScore": score,
        "severity": severity,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(EMIT_URL, json=payload)
    except Exception as e:
        print(f"[Emitter Error] Could not reach backend: {e}")


async def emit_session_start(session_id, ip, city, country):
    """
    Announce a new SSH session so the dashboard's OSINT card populates.

    Previously only the browser terminal emitted this, which meant a real SSH
    attacker left the entire attacker-profile panel stuck on "AWAITING..." --
    the panel most worth watching during a live demo.
    """
    payload = {
        "sessionId": session_id,
        "ip": ip,
        "geo": f"{city}, {country}",
        "type": "SSH BRUTE-FORCE / UNAUTHORIZED ACCESS",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(SESSION_START_URL, json=payload)
    except Exception as e:
        print(f"[Emitter Error] Could not announce session: {e}")
