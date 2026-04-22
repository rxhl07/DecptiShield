import httpx
import json
import sys
import os

# Import our config from the backend folder to get the URL
# Since honeypot is a separate folder, we'll point to the URL directly for now 
# or you can use your .env loader logic.
OLLAMA_URL = "http://localhost:11434/api/generate"

async def get_ai_response(command: str, persona_context: str):
    """
    Sends the attacker's command to Llama 3 and gets a hallucinated terminal output.
    """
    
    # The System Prompt is the most important part. 
    # It forces the AI to stay in character.
    system_prompt = f"""
    You are a professional Linux System Administrator for a high-security production server.
    Current Persona: {persona_context}
    
    Rules:
    1. Act ONLY as a Linux terminal. 
    2. Do NOT provide explanations, apologies, or conversational text.
    3. If a command is successful, show the standard Linux output.
    4. If a command is malicious (like rm -rf /), simulate the result realistically or show a permission denied error.
    5. Keep responses concise and technical.
    6. Your hostname is 'prod-db-01' and current user is 'admin'.
    """

    payload = {
        "model": "llama3",
        "prompt": f"{system_prompt}\n\nAttacker Command: {command}",
        "stream": False,  # Set to False for a simpler MVP response
        "options": {
            "temperature": 0.7 # A bit of creativity makes the 'hallucination' more realistic
        }
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "bash: command not found")
            
    except Exception as e:
        print(f"[AI Error] Could not connect to Ollama: {e}")
        return f"sh: {command}: connection to AI backend lost"

# Quick test block
if __name__ == "__main__":
    import asyncio
    test_cmd = "ls -la /etc/passwd"
    print(f"Testing AI with command: {test_cmd}")
    reply = asyncio.run(get_ai_response(test_cmd, "Ubuntu 22.04 Web Server"))
    print(f"AI Output:\n{reply}")