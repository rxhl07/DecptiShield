import socket
import threading
import paramiko
import asyncio
from session_handler import SessionHandler
import os

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(f"[Auth] Login attempt: {username} / {password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, sheight, modes):
        return True

# A simple wrapper to make the Paramiko channel work with your Async SessionHandler
class AsyncChannelWrapper:
    def __init__(self, chan):
        self.chan = chan

    async def read(self, n):
        # Run the blocking read in a background thread so it doesn't freeze the async loop
        return await asyncio.to_thread(self.chan.recv, n)

    def write(self, data):
        self.chan.send(data)

    async def drain(self):
        pass # Not needed for paramiko channels

    def close(self):
        self.chan.close()

    async def wait_closed(self):
        pass

# THIS IS THE FUNCTION YOU WERE MISSING
def handle_sync_connection(client, addr):
    print(f"[Honeypot] New connection from {addr[0]}")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        transport = paramiko.Transport(client)
        
        # --- NEW CODE: Auto-generate the key if it's missing ---
        if not os.path.exists('server.key'):
            print("[Honeypot] Generating new RSA Host Key (server.key)...")
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file('server.key')
        # -------------------------------------------------------
        
        host_key = paramiko.RSAKey(filename='server.key')
        transport.add_server_key(host_key)
        
        server = HoneypotServer()
        transport.start_server(server=server)
        
        chan = transport.accept(20)
        if chan is None:
            return

        wrapper = AsyncChannelWrapper(chan)
        handler = SessionHandler(reader=wrapper, writer=wrapper, attacker_ip=addr[0])
        
        loop.run_until_complete(handler.start())
        
    except Exception as e:
        print(f"[SSH Error] {e}")
    finally:
        loop.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Ensure the socket can be reused immediately after restarting the script
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # WE ARE USING PORT 2222
    server_socket.bind(('0.0.0.0', 2222))
    server_socket.listen(5)
    
    print("--- DECEPTISHIELD HONEYPOT (THREADED MODE) ---")
    print("Listening on Port 2222...")
    
    while True:
        client, addr = server_socket.accept()
        t = threading.Thread(target=handle_sync_connection, args=(client, addr))
        t.start()
    
if __name__ == "__main__":
    main()