#backend 
pip install fastapi uvicorn python-socketio httpx pydantic
uvicorn main:socket_app --port 8000 --reload

#frontend 
npm run dev

#honeypot
python ssh_server.py

#attackers terminal
ssh admin@192.168.1.100