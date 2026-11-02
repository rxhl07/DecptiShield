#backend 
uvicorn main:socket_app --port 8000 --reload
uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload

#frontend 
npm run dev

#honeypot-Required only if testing from terminal , not required for web
python ssh_server.py

#attackers terminal
ssh admin@192.168.1.100

#external connection
ngrok tcp 2222
ssh -p XXXX admin@0.tcp.in.ngrok.io
