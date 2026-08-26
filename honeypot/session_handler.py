import asyncio
import sys
from pathlib import Path

from ollama_client import get_ai_response
from threat_scorer import calculate_threat_score
from geo_enrichment import get_geolocation
from db_writer import db_writer
from socket_emitter import emit_to_backend, emit_session_start

# Same command engine the web terminal uses, so both paths behave identically.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import command_engine
from shared.command_engine import VirtualFileSystem, USERNAME, HOSTNAME


class SessionHandler:
    def __init__(self, reader, writer, attacker_ip):
        self.reader = reader
        self.writer = writer
        self.attacker_ip = attacker_ip
        self.session_id = None
        self.persona = "Ubuntu 22.04 LTS (Production Database Server)"
        # Per-session state. The honeypot previously had none at all, so every
        # command went to the model with no memory of what came before.
        self.vfs = VirtualFileSystem()

    def prompt_bytes(self):
        """Bash shows the working directory, abbreviating $HOME to ~."""
        cwd = self.vfs.cwd
        display = "~" + cwd[len(command_engine.HOME):] if cwd.startswith(command_engine.HOME) else cwd
        return f"{USERNAME}@{HOSTNAME}:{display}$ ".encode()

    async def respond(self, command):
        """
        Produce the output for one command. Tiers 0/1/2/4 answer locally in
        microseconds; only the long tail reaches the model.
        """
        self.vfs.record(command)
        result = command_engine.handle_command(command, self.vfs)

        if result.intel:
            print(f"[INTEL] {self.session_id}: {result.intel}")

        if not result.needs_llm:
            return result.output

        raw = await get_ai_response(command, self.persona, self.vfs)
        text = command_engine.sanitize_llm_output(raw)
        validated = command_engine.validate_against_state(text, command, self.vfs)
        if validated is None:
            print(f"[Validation] rejected model output for: {command}")
            return command_engine.fallback_output(command)
        # Remember it, so asking again gives the same answer.
        command_engine.remember_llm_output(command, validated, self.vfs)
        return validated

    async def start(self):
        """Initializes the session and starts the command loop."""
        # 1. Get GeoData
        geo = await get_geolocation(self.attacker_ip)
        
        # 2. Create entry in MongoDB
        self.session_id = db_writer.create_session(
            self.attacker_ip, geo['city'], geo['country']
        )

        # 2b. Tell the dashboard who just connected, so the OSINT card fills in.
        await emit_session_start(
            self.session_id, self.attacker_ip, geo['city'], geo['country']
        )

        # 3. Send welcome banner to the attacker
        self.writer.write(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n".encode())
        await self.writer.drain()

        # 4. Main Command Loop
        try:
            self.writer.write(self.prompt_bytes())
            await self.writer.drain()
            
            command_buffer = ""
            
            while True:
                # Read ONE character at a time to prevent lag
                char = await self.reader.read(1)
                if not char:
                    break
                
                char_decoded = char.decode('utf-8', errors='ignore')
                
                # --- IF THE ATTACKER HITS 'ENTER' ---
                if char_decoded in ('\r', '\n'):
                    self.writer.write(b"\r\n") # Move cursor to the next line
                    await self.writer.drain()
                    
                    command = command_buffer.strip()
                    command_buffer = "" # Reset the buffer for the next command
                    
                    if command.lower() in ['exit', 'quit']:
                        break
                    
                    if command:
                        response_text = await self.respond(command)

                        # Calculate Threat Level
                        score, severity = calculate_threat_score(command)

                        # Log to DB and push to the frontend Live Feed
                        db_writer.log_event(self.session_id, command, response_text, score, severity)
                        await emit_to_backend(self.session_id, command, response_text, score, severity)

                        # Only write a line back if the command actually produces
                        # output -- `touch` and friends print nothing on a real box.
                        if response_text:
                            formatted = response_text.replace("\r\n", "\n").replace("\n", "\r\n")
                            self.writer.write((formatted + "\r\n").encode())
                            await self.writer.drain()

                    # Print new prompt for the next line
                    self.writer.write(self.prompt_bytes())
                    await self.writer.drain()
                
                # --- IF THE ATTACKER HITS 'BACKSPACE' ---
                elif char_decoded in ('\x08', '\x7f'): 
                    if len(command_buffer) > 0:
                        command_buffer = command_buffer[:-1]
                        # Visual trick: move cursor back, print blank space, move cursor back
                        self.writer.write(b"\x08 \x08") 
                        await self.writer.drain()
                
                # --- NORMAL TYPING ---
                else:
                    command_buffer += char_decoded
                    # ECHO the character back instantly so there is NO lag!
                    self.writer.write(char)
                    await self.writer.drain()

        except Exception as e:
            print(f"[Handler Error] Session {self.session_id}: {e}")
        finally:
            print(f"[Honeypot] Session {self.session_id} closed.")
            self.writer.close()
            await self.writer.wait_closed()