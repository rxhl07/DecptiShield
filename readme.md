#backend (also starts the SSH honeypot on port 2222)
cd backend
uvicorn main:socket_app --port 8000 --reload
uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload

#model
ollama pull llama3
Set OLLAMA_MODEL in backend/.env to use a different model.

#frontend 
npm run dev

#attackers terminal
ssh admin@192.168.1.100

#external connection
ngrok tcp 2222
ssh -p XXXX admin@0.tcp.in.ngrok.io

#testing from a second laptop
Run the backend on the laptop with the GPU, then see tests/baseline/README.md
