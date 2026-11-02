import asyncio
import os
import uuid
import asyncssh
import httpx
from socketio_server import sio
import session_registry

ssh_sessions = {}


def get_severity_label(score: int) -> str:
  if score >= 80:
    return "CRITICAL"
  if score >= 55:
    return "HIGH"
  if score >= 30:
    return "MEDIUM"
  return "LOW"


async def notify_attacker_connected(client_ip: str, session_id: str = None):
  try:
    async with httpx.AsyncClient(timeout=5.0) as client:
      await client.post(
          "http://127.0.0.1:8000/internal/attacker-connected",
          json={
              "ip": client_ip,
              "source": "SSH INTERCEPT",
              "sessionId": session_id,
          },
      )
  except Exception as e:
    print(f"[SSH Alert Error] Could not register attacker IP: {e}")


class SSHHoneypotSession(asyncssh.SSHServerSession):

  def __init__(self, client_ip: str, session_id: str = None):
    self._input = ""
    self._chan = None
    self.client_ip = client_ip
    self.session_id = session_id or f"SSH-{str(uuid.uuid4())[:6]}"
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
    self._chan.write(
        "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-76-generic x86_64)\r\n\r\n"
    )
    self._chan.write("ubuntu@prod-db-01:~$ ")

  def data_received(self, data, datatype):
    for char in data:
      if char in ("\r", "\n"):
        self._chan.write("\r\n")
        cmd = self._input.strip()
        self._input = ""
        if cmd:
          asyncio.create_task(self.handle_command(cmd))
        else:
          self._chan.write("ubuntu@prod-db-01:~$ ")
      elif char in ("\x7f", "\x08"):
        if len(self._input) > 0:
          self._input = self._input[:-1]
          self._chan.write("\b \b")
      elif char == "\x03":
        self._input = ""
        self._chan.write("^C\r\nubuntu@prod-db-01:~$ ")
      else:
        self._input += char
        self._chan.write(char)

  async def handle_command(self, command: str):
    cmd_lower = command.lower()

    # Session termination
    if cmd_lower in ["exit", "logout"]:
      self._chan.write("logout\r\nConnection to prod-db-01 closed.\r\n")
      self._chan.exit(0)
      return

    # Virtual File System (VFS) State Tracking
    parts = command.split()
    base_cmd = parts[0] if parts else ""

    if base_cmd == "cd":
      if len(parts) == 1 or parts[1] == "~":
        self.cwd = "/home/ubuntu"
      elif parts[1] == "..":
        if self.cwd != "/":
          self.cwd = "/".join(self.cwd.split("/")[:-1])
          if self.cwd == "":
            self.cwd = "/"
      elif parts[1] == "/":
        self.cwd = "/"
      else:
        self.cwd = (
            parts[1]
            if parts[1].startswith("/")
            else f"{self.cwd}/{parts[1]}".replace("//", "/")
        )

    elif base_cmd in ["touch", "mkdir", "nano", "vim"]:
      for f in parts[1:]:
        if not f.startswith("-"):
          new_f = f if f.startswith("/") else f"{self.cwd}/{f}"
          new_f = new_f.replace("//", "/")
          if new_f not in self.created_files:
            self.created_files.append(new_f)

    elif base_cmd in ["rm", "rmdir"]:
      for f in parts[1:]:
        if not f.startswith("-"):
          target_f = f if f.startswith("/") else f"{self.cwd}/{f}"
          target_f = target_f.replace("//", "/")
          if target_f in self.created_files:
            self.created_files.remove(target_f)
          if target_f not in self.deleted_files:
            self.deleted_files.append(target_f)

    # Threat Scoring Calculation
    score = 10
    if any(
        k in cmd_lower
        for k in [
            "sudo",
            "rm",
            "wget",
            "curl",
            "chmod",
            "shadow",
            "nmap",
            "/etc",
        ]
    ):
      score = 90
    elif any(
        k in cmd_lower
        for k in ["cat", "ls", "cd", "find", "grep", "netstat", "ps"]
    ):
      score = 40

    self.total_score += score
    self.command_count += 1
    avg_score = int(self.total_score / self.command_count)

    # Silent state modifications
    if cmd_lower.startswith(
        ("cd ", "touch ", "mkdir ", "export ", "rm ", "rmdir ")
    ):
      ai_output = ""
      self._chan.write("ubuntu@prod-db-01:~$ ")
    else:
      cwd_files = [
          f.split("/")[-1]
          for f in self.created_files
          if ("/".join(f.split("/")[:-1]) == self.cwd)
          or (self.cwd == "/" and f.count("/") == 1)
      ]
      files_str = f"Files in cwd: {', '.join(cwd_files)}" if cwd_files else ""

      prompt = (
          "You are a low-level Linux terminal simulator for host prod-db-01."
          f" Working Directory: {self.cwd}. {files_str}. Command: {command}."
          " Respond strictly with the exact command stdout/stderr. Do not add"
          " conversational text."
      )
      payload = {
          "model": "llama3",
          "prompt": prompt,
          "stream": False,
          "options": {
              "temperature": 0.05,
              "num_ctx": 2048,
              "num_predict": 256,
          },
      }

      try:
        async with httpx.AsyncClient(timeout=30.0) as client:
          res = await client.post(
              "http://localhost:11434/api/generate", json=payload
          )
          ai_output = res.json().get("response", "bash: command not found")
      except Exception:
        ai_output = "bash: command execution failed\n"

      formatted = ai_output.replace("\r\n", "\n").replace("\n", "\r\n")
      if not formatted.endswith("\r\n"):
        formatted += "\r\n"
      self._chan.write(formatted)
      self._chan.write("ubuntu@prod-db-01:~$ ")

    telemetry = {
        "sessionId": self.session_id,
        "command": command,
        "response": ai_output if ai_output else "[silent execution]",
        "threatScore": avg_score,
        "severity": get_severity_label(avg_score),
    }
    await session_registry.record_command(
        self.session_id,
        command,
        telemetry["severity"],
        avg_score,
        ip=self.client_ip,
        response=ai_output,
    )
    await sio.emit("live_feed_update", telemetry)


class SSHHoneypotServer(asyncssh.SSHServer):

  def __init__(self):
    self.client_ip = "127.0.0.1"
    # asyncssh creates one SSHHoneypotServer per connection -> one session id
    self.session_id = f"SSH-{str(uuid.uuid4())[:6]}"

  def connection_made(self, conn):
    peername = conn.get_extra_info("peername")
    if peername:
      self.client_ip = peername[0]
      print(f"[SSH Server] Inbound connection detected from: {self.client_ip}")

  def connection_lost(self, exc):
    asyncio.create_task(session_registry.close_session(self.session_id))

  def password_auth_supported(self):
    return True

  def validate_password(self, username, password):
    asyncio.create_task(
        session_registry.register_session(
            self.session_id, self.client_ip, "SSH"
        )
    )
    asyncio.create_task(
        notify_attacker_connected(self.client_ip, self.session_id)
    )
    return True

  def session_requested(self):
    # Safety net in case auth happened without validate_password (idempotent)
    asyncio.create_task(
        session_registry.register_session(
            self.session_id, self.client_ip, "SSH"
        )
    )
    return SSHHoneypotSession(self.client_ip, self.session_id)


async def start_ssh_honeypot(port=2222):
  key_path = "honeypot_host_key"
  if not os.path.exists(key_path):
    key = asyncssh.generate_private_key("ssh-rsa")
    with open(key_path, "wb") as f:
      f.write(key.export_private_key())

  server = await asyncssh.create_server(
      SSHHoneypotServer, "", port, server_host_keys=[key_path], line_editor=False
  )
  print(f"[SSH Honeypot] Daemon active and listening on port {port}...")
  return server