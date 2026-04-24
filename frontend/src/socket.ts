import { io } from 'socket.io-client';

// Point this to your FastAPI backend port
const BACKEND_URL = "http://localhost:8000";

export const socket = io(BACKEND_URL, {
    autoConnect: true,
    reconnection: true,
});