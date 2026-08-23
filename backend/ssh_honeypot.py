import asyncio
import asyncssh
import sys
import httpx
import json
import uuid
import os
from socketio_server import sio

# Dynamic session tracking for SSH clients
ssh_sessions = {}

def get_severity_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

class SSHHoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, client_ip: str):
        self._input = ''
        self._chan = None
        self.client_ip = client_ip
        self.session_id = f"SSH-{str(uuid.uuid4())[:6]}"
        self.cwd = "/home/ubuntu"
        self.created_files = []
        self.deleted_files = []
        self.total_score = 0
        self.command_count = 0

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def session_started(self):
        # Banner displayed to attacker on login
        self._chan.write("Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-76-generic x86_64)\r\n\r\n")
        self._chan.write("ubuntu@prod-db-01:~$ ")

    def data_received(self, data, datatype):
        for char in data:
            if char in ('\r', '\n'):
                self._chan.write('\r\n')
                cmd = self._input.strip()
                self._input = ''
                if cmd:
                    asyncio.create_task(self.handle_command(cmd))
                else:
                    self._chan.write("ubuntu@prod-db-01:~$ ")
            elif char in ('\x7f', '\x08'):  # Backspace
                if len(self._input) > 0:
                    self._input = self._input[:-1]
                    self._chan.write('\b \b')
            elif char == '\x03':  # Ctrl+C
                self._input = ''
                self._chan.write('^C\r\nubuntu@prod-db-01:~$ ')
            else:
                self._input += char
                self._chan.write(char)

    async def handle_command(self, command: str):
        cmd_lower = command.lower()

        # Handle exit
        if cmd_lower in ["exit", "logout"]:
            self._chan.write("logout\r\nConnection to prod-db-01 closed.\r\n")
            self._chan.exit(0)
            return

        # Basic VFS tracking
        parts = command.split()
        if parts[0] == "cd" and len(parts) > 1:
            self.cwd = parts[1] if parts[1].startswith("/") else f"{self.cwd}/{parts[1]}"
        elif parts[0] in ["touch", "mkdir"] and len(parts) > 1:
            self.created_files.append(f"{self.cwd}/{parts[1]}")

        # Threat scoring calculation
        score = 10
        if any(k in cmd_lower for k in ["sudo", "rm", "wget", "curl", "chmod", "shadow", "nmap", "/etc"]):
            score = 90
        elif any(k in cmd_lower for k in ["cat", "ls", "cd", "find", "grep", "netstat", "ps"]):
            score = 40

        self.total_score += score
        self.command_count += 1
        avg_score = int(self.total_score / self.command_count)

        # Silent commands return immediately
        if cmd_lower.startswith(("cd ", "touch ", "mkdir ", "export ")):
            ai_output = ""
            self._chan.write("ubuntu@prod-db-01:~$ ")
        else:
            prompt = (
                f"You are a vulnerable Ubuntu Linux server (prod-db-01). "
                f"CWD: {self.cwd}. User created: {', '.join(self.created_files)}. "
                f"Command: {command}. Respond ONLY with exact terminal output. No explanations."
            )
            payload = {
                "model": "llama3",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_ctx": 2048, "num_predict": 256}
            }

            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    res = await client.post("http://localhost:11434/api/generate", json=payload)
                    ai_output = res.json().get("response", "bash: command not found")
            except Exception:
                ai_output = "bash: command execution failed\n"

            formatted = ai_output.replace('\r\n', '\n').replace('\n', '\r\n')
            if not formatted.endswith('\r\n'):
                formatted += '\r\n'
            self._chan.write(formatted)
            self._chan.write("ubuntu@prod-db-01:~$ ")

        telemetry = {
            "sessionId": self.session_id,
            "command": command,
            "response": ai_output,
            "threatScore": avg_score,
            "severity": get_severity_label(avg_score)
        }
        await sio.emit('live_feed_update', telemetry)


class SSHHoneypotServer(asyncssh.SSHServer):
    def __init__(self, client_ip: str):
        self.client_ip = client_ip

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return True

    def session_requested(self):
        return SSHHoneypotSession(self.client_ip)


async def start_ssh_honeypot(port=2222):
    key_path = "honeypot_host_key"
    
    # Generate once and persist to disk
    if not os.path.exists(key_path):
        key = asyncssh.generate_private_key('ssh-rsa')
        with open(key_path, "wb") as f:
            f.write(key.export_private_key())
            
    server = await asyncssh.create_server(
        lambda: SSHHoneypotServer("127.0.0.1"),
        '',
        port,
        server_host_keys=[key_path],
        line_editor=False
    )
    print(f"[SSH Honeypot] Daemon active and listening on port {port}...")
    return server