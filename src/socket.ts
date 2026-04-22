import { io } from 'socket.io-client';

// This should match the port your FastAPI backend is running on
const SOCKET_URL = 'http://localhost:5000';

export const socket = io(SOCKET_URL, {
    autoConnect: false, // We only connect when the terminal is opened
});