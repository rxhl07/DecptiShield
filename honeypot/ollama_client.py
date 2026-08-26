import sys
from pathlib import Path

import httpx

import config

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import command_engine


# One client for the whole process, so we reuse the connection pool instead of
# paying a fresh TCP+TLS handshake on every command. Matters most when Ollama
# is on another machine.
_client = None


def _get_client():
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30.0)
    return _client


async def get_ai_response(command, persona_context, vfs=None):
    """
    Ask the model for one command's output. Returns raw text -- the caller is
    responsible for sanitising and validating it.
    """
    if vfs is None:
        vfs = command_engine.VirtualFileSystem()

    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": command_engine.build_messages(command, vfs, persona_context),
        "stream": False,
        # Ollama unloads an idle model after ~5 minutes and the reload costs
        # several seconds. -1 keeps it resident, which matters mid-demo.
        "keep_alive": -1,
        "options": {
            "num_predict": 256,   # terminal output is short; don't let it ramble
            "temperature": 0.4,
        },
    }

    try:
        response = await _get_client().post(
            command_engine.chat_url(config.OLLAMA_URL), json=payload)
        response.raise_for_status()
        return response.json().get("message", {}).get("content", "")
    except Exception as e:
        # Return empty rather than an error string: the caller falls back to a
        # deterministic response, so an unreachable model degrades quietly
        # instead of announcing that this is a honeypot.
        print(f"[AI Error] Could not reach Ollama at {config.OLLAMA_URL}: {e}")
        return ""


# Quick manual check: python ollama_client.py
if __name__ == "__main__":
    import asyncio
    from shared.command_engine import VirtualFileSystem

    test_cmd = "cat /var/log/auth.log"
    print(f"Testing AI with command: {test_cmd}")
    reply = asyncio.run(get_ai_response(test_cmd, "Ubuntu 22.04 Web Server",
                                        VirtualFileSystem()))
    print(f"AI Output:\n{reply}")
