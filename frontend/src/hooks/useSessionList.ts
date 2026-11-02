import { useEffect, useState } from 'react';
import { socket } from '../socket';

// Live list of attacker sessions: initial fetch + `session_update` socket events.
// (Moved verbatim from Sessions.tsx so the Sessions page and the dashboard sidebar share it.)

const BACKEND_URL = 'http://localhost:8000';

export interface SessionSummary {
    sessionId: string;
    ip: string;
    source: string;
    startTime: string;
    endTime: string | null;
    status: 'active' | 'closed';
    threatScore: number;
    commandCount: number;
}

// Active sessions first, newest first within each group
function sortSessions(list: SessionSummary[]) {
    return [...list].sort((a, b) => {
        if (a.status !== b.status) return a.status === 'active' ? -1 : 1;
        return (b.startTime || '').localeCompare(a.startTime || '');
    });
}

export function useSessionList() {
    const [sessions, setSessions] = useState<SessionSummary[]>([]);
    const [backendDown, setBackendDown] = useState(false);

    useEffect(() => {
        const load = () => {
            fetch(`${BACKEND_URL}/api/sessions`)
                .then((res) => res.json())
                .then((data) => {
                    if (Array.isArray(data)) setSessions(sortSessions(data));
                    setBackendDown(false);
                })
                .catch(() => setBackendDown(true));
        };

        const onSessionUpdate = (s: SessionSummary) => {
            if (!s || !s.sessionId) return;
            setSessions((prev) => sortSessions([...prev.filter((p) => p.sessionId !== s.sessionId), s]));
        };

        load();
        // Re-sync after (re)connects so nothing is missed while disconnected
        socket.on('connect', load);
        socket.on('session_update', onSessionUpdate);
        // Reconnect only if fully shut down (the attacker terminal disconnects the shared socket);
        // calling connect() while still connecting sends a duplicate CONNECT that the server rejects.
        if (!socket.active) socket.connect();

        return () => {
            socket.off('connect', load);
            socket.off('session_update', onSessionUpdate);
        };
    }, []);

    return { sessions, backendDown, backendUrl: BACKEND_URL };
}
