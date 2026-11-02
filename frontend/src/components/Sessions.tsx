import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldAlert, ArrowLeft, ChevronRight } from 'lucide-react';
import { socket } from '../socket';

const BACKEND_URL = 'http://localhost:8000';

interface SessionSummary {
    sessionId: string;
    ip: string;
    source: string;
    startTime: string;
    endTime: string | null;
    status: 'active' | 'closed';
    threatScore: number;
    commandCount: number;
}

function scoreColor(score: number) {
    if (score >= 80) return '#EF4444';
    if (score >= 55) return '#F59E0B';
    return '#10B981';
}

// Active sessions first, newest first within each group
function sortSessions(list: SessionSummary[]) {
    return [...list].sort((a, b) => {
        if (a.status !== b.status) return a.status === 'active' ? -1 : 1;
        return (b.startTime || '').localeCompare(a.startTime || '');
    });
}

function fmtTime(iso: string) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function Sessions() {
    const navigate = useNavigate();
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

    const activeCount = sessions.filter((s) => s.status === 'active').length;

    return (
        <div className="min-h-screen w-full bg-[#020202] text-slate-300 relative pb-20 selection:bg-[#2D5BFF]/30">
            <div className="absolute inset-0 pointer-events-none opacity-[0.03] bg-[linear-gradient(rgba(255,255,255,0)_50%,rgba(0,0,0,1)_50%)] bg-[length:100%_4px] z-0" />

            <header className="relative z-20 border-b border-white/10 bg-[#050505] px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <ShieldAlert size={18} className="text-[#EF4444] animate-pulse" />
                    <h1 className="text-sm font-mono font-black tracking-[0.2em] uppercase text-white">DeceptiShield // Sessions</h1>
                </div>
                <div className="font-mono text-xs flex items-center gap-6">
                    <span className="text-[#2D5BFF]">ACTIVE: {activeCount}</span>
                    <button onClick={() => navigate('/')} className="flex items-center gap-2 text-slate-500 hover:text-white tracking-widest transition-colors">
                        <ArrowLeft size={14} /> HOME
                    </button>
                </div>
            </header>

            <main className="relative z-10 max-w-[1600px] mx-auto p-8">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="bg-[#050505] border border-white/10 rounded-lg shadow-2xl flex flex-col overflow-hidden"
                >
                    <div className="bg-[#0A0A0B] border-b border-white/10 px-4 py-2.5 flex items-center justify-between">
                        <span className="font-mono text-[10px] text-slate-400 font-bold uppercase tracking-widest">Intercepted_Sessions</span>
                        <span className="font-mono text-[9px] text-slate-600 tracking-wider hidden sm:block">~/deceptishield/sessions</span>
                    </div>

                    <div className="p-8 overflow-x-auto">
                        {sessions.length === 0 ? (
                            <div className="text-center p-8 text-slate-500 font-mono text-sm">
                                No current sessions
                                {backendDown && (
                                    <p className="text-[10px] text-red-400/70 mt-3">Backend unreachable at {BACKEND_URL}</p>
                                )}
                            </div>
                        ) : (
                            <table className="w-full font-mono text-sm min-w-[720px]">
                                <thead>
                                    <tr className="text-[10px] font-bold text-slate-500 uppercase text-left">
                                        <th className="px-4 py-3">Session ID</th>
                                        <th className="px-4 py-3">Attacker IP</th>
                                        <th className="px-4 py-3">Start Time</th>
                                        <th className="px-4 py-3">Status</th>
                                        <th className="px-4 py-3 text-center">Threat Score</th>
                                        <th className="px-4 py-3 text-center">Commands</th>
                                        <th className="px-4 py-3" />
                                    </tr>
                                </thead>
                                <tbody>
                                    {sessions.map((s) => {
                                        const active = s.status === 'active';
                                        const color = scoreColor(s.threatScore);
                                        return (
                                            <tr
                                                key={s.sessionId}
                                                onClick={() => navigate(`/dashboard/${encodeURIComponent(s.sessionId)}`)}
                                                className="border-t border-white/5 cursor-pointer hover:bg-white/[0.04] transition-colors"
                                            >
                                                <td className="px-4 py-4 text-white">{s.sessionId}</td>
                                                <td className="px-4 py-4">{s.ip}</td>
                                                <td className="px-4 py-4 text-slate-400 text-xs">{fmtTime(s.startTime)}</td>
                                                <td className="px-4 py-4">
                                                    <span className={`inline-flex items-center gap-2 text-[10px] font-black tracking-widest ${active ? 'text-[#10B981]' : 'text-slate-500'}`}>
                                                        <span className={`w-2 h-2 rounded-full ${active ? 'bg-[#10B981] animate-pulse' : 'bg-slate-600'}`} />
                                                        {active ? 'ACTIVE' : 'CLOSED'}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-4 text-center font-bold" style={{ color }}>{s.threatScore}</td>
                                                <td className="px-4 py-4 text-center">{s.commandCount}</td>
                                                <td className="px-4 py-4 text-right text-slate-600"><ChevronRight size={16} className="inline" /></td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        )}
                    </div>
                </motion.div>
            </main>
        </div>
    );
}
