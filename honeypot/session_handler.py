import asyncio
from ollama_client import get_ai_response
from threat_scorer import calculate_threat_score
from geo_enrichment import get_geolocation
from db_writer import db_writer
from socket_emitter import emit_to_backend

class SessionHandler:
    def __init__(self, reader, writer, attacker_ip):
        self.reader = reader
        self.writer = writer
        self.attacker_ip = attacker_ip
        self.session_id = None
        self.persona = "Ubuntu 22.04 LTS (Production Database Server)"

    async def start(self):
        """Initializes the session and starts the command loop."""
        # 1. Get GeoData
        geo = await get_geolocation(self.attacker_ip)
        
        # 2. Create entry in MongoDB
        self.session_id = db_writer.create_session(
            self.attacker_ip, geo['city'], geo['country']
        )
        
        # 3. Send welcome banner to the attacker
        self.writer.write(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n".encode())
        await self.writer.drain()

        # 4. Main Command Loop
        try:
            self.writer.write(b"admin@prod-db-01:~$ ")
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
                        # Send the fully typed command to Llama 3
                        ai_response = await get_ai_response(command, self.persona)
                        
                        # Calculate Threat Level
                        score, severity = calculate_threat_score(command)
                        
                        # Log to DB and push to the frontend Live Feed
                        db_writer.log_event(self.session_id, command, ai_response, score, severity)
                        await emit_to_backend(self.session_id, command, ai_response, score, severity)

                        # Print AI response back to the attacker
                        formatted_response = ai_response.replace("\n", "\r\n") + "\r\n"
                        self.writer.write(formatted_response.encode())
                        await self.writer.drain()

                    # Print new prompt for the next line
                    self.writer.write(b"admin@prod-db-01:~$ ")
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