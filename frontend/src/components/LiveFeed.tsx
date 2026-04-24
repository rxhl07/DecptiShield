import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Activity } from 'lucide-react';
import { socket } from '../socket';

export interface LogEntry {
    id: string;
    timestamp: string;
    command: string;
    risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    score: number;
}

const RISK_CONFIG: Record<LogEntry['risk'], { color: string; bg: string; border: string }> = {
    LOW: { color: '#10B981', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.3)' },
    MEDIUM: { color: '#F59E0B', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.3)' },
    HIGH: { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)' },
    CRITICAL: { color: '#EF4444', bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.4)' },
};

export default function LiveFeed() {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        // Debug: Log to see if the socket is actually connected
        console.log("Socket status on mount:", socket.connected ? "Connected" : "Disconnected");

        const handleNewAttack = (data: any) => {
            console.log("🚨 Data received from socket:", data); // THIS IS YOUR KEY DEBUG LINE

            const newLog: LogEntry = {
                // Ensure we have a truly unique ID
                id: (data.sessionId || 'web') + '-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
                timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
                command: data.command || 'Unknown Command',
                risk: (data.severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') || 'LOW',
                score: data.threatScore || 0
            };

            setLogs((prev) => {
                const updatedLogs = [...prev, newLog];
                return updatedLogs.slice(-30);
            });
        };

        // Ensure we aren't attaching multiple listeners
        socket.off('live_feed_update');
        socket.on('live_feed_update', handleNewAttack);

        return () => {
            socket.off('live_feed_update', handleNewAttack);
        };
    }, []);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTo({
                top: scrollRef.current.scrollHeight,
                behavior: 'smooth'
            });
        }
    }, [logs]);

    return (
        <div className="flex flex-col h-full flex-grow">
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <Activity size={16} className="text-[#10B981]" />
                    <span className="text-xs font-black tracking-widest uppercase text-white">Live Command Feed</span>
                </div>
            </div>

            <div className="flex items-center gap-3 px-4 py-3 mb-2 rounded-xl font-mono text-[10px] font-bold text-slate-500 uppercase bg-white/5 border border-white/5">
                <span className="w-20 lg:w-32">TIME</span>
                <span className="flex-1">COMMAND</span>
                <span className="w-24 text-center">RISK</span>
            </div>

            <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-2 pr-2 scroll-smooth">
                {logs.length === 0 && (
                    <div className="text-center p-8 text-slate-500 font-mono text-sm animate-pulse">
                        Awaiting adversarial contact...
                    </div>
                )}
                <AnimatePresence initial={false}>
                    {logs.map((entry) => {
                        const cfg = RISK_CONFIG[entry.risk] || RISK_CONFIG.LOW;
                        return (
                            <motion.div
                                key={entry.id}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, transition: { duration: 0.2 } }}
                                className="flex items-center gap-3 px-4 py-4 rounded-xl font-mono text-sm"
                                style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderLeft: `4px solid ${cfg.color}` }}
                            >
                                <span className="w-20 lg:w-32 text-slate-500 text-xs">{entry.timestamp.slice(11)}</span>
                                <span className="flex-1 text-white">
                                    <Terminal size={14} className="inline mr-2 opacity-50" style={{ color: cfg.color }} />
                                    {entry.command}
                                </span>
                                <span className="w-24 text-center px-2 py-1.5 rounded text-[10px] font-black tracking-widest" style={{ color: cfg.color, border: `1px solid ${cfg.border}` }}>
                                    {entry.risk}
                                </span>
                            </motion.div>
                        );
                    })}
                </AnimatePresence>
            </div>
        </div>
    );
}