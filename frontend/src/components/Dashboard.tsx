import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { TerminalSquare, ShieldAlert } from 'lucide-react';
import LiveFeed from './LiveFeed';
import ReportButton from './ReportButton';

// --- Helper Functions & Data ---
const SESSION = {
    target: 'ubuntu@prod-db-01',
    attackerIp: '185.220.101.47',
    threatScore: 87,
};

function scoreColor(score: number) {
    if (score >= 80) return '#EF4444';
    if (score >= 55) return '#F59E0B';
    return '#10B981';
}

function scoreLabel(score: number) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 55) return 'HIGH';
    return 'LOW';
}

// --- Terminal Window Wrapper Component ---
function TerminalWindow({ title, path, children, delay = 0, className = '' }: { title: string, path: string, children: React.ReactNode, delay?: number, className?: string }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay }}
            className={`bg-[#050505] border border-white/10 rounded-lg shadow-2xl flex flex-col overflow-hidden ${className}`}
        >
            <div className="bg-[#0A0A0B] border-b border-white/10 px-4 py-2.5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <TerminalSquare size={14} className="text-[#2D5BFF]" />
                    <span className="font-mono text-[10px] text-slate-400 font-bold uppercase tracking-widest">{title}</span>
                </div>
                <span className="font-mono text-[9px] text-slate-600 tracking-wider hidden sm:block">{path}</span>
            </div>
            <div className="p-8 flex-1 flex flex-col">
                {children}
            </div>
        </motion.div>
    );
}

// --- High-End Threat Ring Component ---
function ModernThreatRing({ score }: { score: number }) {
    const radius = 50;
    const circumference = 2 * Math.PI * radius;
    const dash = (score / 100) * circumference;
    const color = scoreColor(score);

    return (
        <div className="relative flex items-center justify-center w-48 h-48">
            <svg width="192" height="192" className="rotate-[-90deg] drop-shadow-2xl">
                {/* Background track */}
                <circle cx="96" cy="96" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />

                {/* Active dashed inner accent */}
                <circle cx="96" cy="96" r={radius - 12} fill="none" stroke={`${color}44`} strokeWidth="1" strokeDasharray="4 6" className="animate-[spin_12s_linear_infinite]" />

                {/* Glowing Progress Arc */}
                <motion.circle
                    initial={{ strokeDasharray: `0 ${circumference}` }}
                    animate={{ strokeDasharray: `${dash} ${circumference}` }}
                    transition={{ duration: 1.5, ease: "easeOut", delay: 0.2 }}
                    cx="96" cy="96" r={radius} fill="none" stroke={color} strokeWidth="6" strokeLinecap="square"
                    style={{ filter: `drop-shadow(0 0 12px ${color}88)` }}
                />
            </svg>

            {/* Centered Readout */}
            <div className="absolute inset-0 flex flex-col items-center justify-center mt-1">
                <span className="font-black text-6xl tracking-tighter text-white">{score}</span>
                <span className="text-[10px] font-mono tracking-widest mt-1 uppercase" style={{ color }}>
                    {scoreLabel(score)}
                </span>
            </div>
        </div>
    );
}

// --- Main Dashboard ---
export default function Dashboard() {
    const [elapsed, setElapsed] = useState(0);

    useEffect(() => {
        const iv = setInterval(() => setElapsed((s) => s + 1), 1000);
        return () => clearInterval(iv);
    }, []);

    const fmtElapsed = (s: number) => {
        const h = Math.floor(s / 3600).toString().padStart(2, '0');
        const m = Math.floor((s % 3600) / 60).toString().padStart(2, '0');
        const sec = (s % 60).toString().padStart(2, '0');
        return `${h}:${m}:${sec}`;
    };

    return (
        <div className="min-h-screen w-full bg-[#020202] text-slate-300 relative pb-20 selection:bg-[#2D5BFF]/30">

            {/* Subtle Scanline Background Overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.03] bg-[linear-gradient(rgba(255,255,255,0)_50%,rgba(0,0,0,1)_50%)] bg-[length:100%_4px] z-0" />

            {/* Global Terminal Header */}
            <header className="relative z-20 border-b border-white/10 bg-[#050505] px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <ShieldAlert size={18} className="text-[#EF4444] animate-pulse" />
                    <h1 className="text-sm font-mono font-black tracking-[0.2em] uppercase text-white">DeceptiShield // SOC</h1>
                </div>
                <div className="font-mono text-xs flex items-center gap-6">
                    <span className="text-red-500 hidden md:block">[{">"} ALERT_ACTIVE]</span>
                    <span className="text-[#2D5BFF]">UPTIME: {fmtElapsed(elapsed)}</span>
                </div>
            </header>

            {/* FIXED ASYMMETRICAL TERMINAL GRID */}
            <main className="relative z-10 max-w-[1600px] mx-auto p-8 grid grid-cols-1 lg:grid-cols-12 gap-8">

                {/* LEFT COLUMN (8/12) */}
                <div className="lg:col-span-8 flex flex-col gap-8">

                    {/* Target Box */}
                    <TerminalWindow title="Active_Intercept" path="~/deceptishield/targets/active.yml" delay={0.1}>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 font-mono">
                            <div className="p-6 bg-white/[0.02] border border-white/5 rounded">
                                <p className="text-[10px] text-slate-500 mb-4">TARGET_ENVIRONMENT:</p>
                                <div className="space-y-2 text-sm">
                                    <p><span className="text-[#2D5BFF]">host:</span> <span className="text-white">ubuntu@prod-db-01</span></p>
                                    <p><span className="text-[#2D5BFF]">protocol:</span> <span className="text-slate-300">SSH / 22</span></p>
                                    <p><span className="text-[#2D5BFF]">status:</span> <span className="text-[#10B981]">TRAPPED</span></p>
                                </div>
                            </div>
                            <div className="p-6 bg-red-500/[0.02] border border-red-500/10 rounded">
                                <p className="text-[10px] text-slate-500 mb-4">ADVERSARY_METADATA:</p>
                                <div className="space-y-2 text-sm">
                                    <p><span className="text-red-400">ip_address:</span> <span className="text-white">185.220.101.47</span></p>
                                    <p><span className="text-red-400">geo_location:</span> <span className="text-slate-300">TOR EXIT NODE</span></p>
                                    <p><span className="text-red-400">connection:</span> <span className="text-red-500 animate-pulse">ESTABLISHED</span></p>
                                </div>
                            </div>
                        </div>
                    </TerminalWindow>

                    {/* Attack Narrative */}
                    <TerminalWindow title="Attack_Narrative" path="/var/log/deceptishield/syslog" delay={0.2}>
                        <div className="space-y-5 font-mono text-sm relative">
                            <div className="absolute left-[31px] top-2 bottom-2 w-[1px] bg-white/10" />
                            {[
                                { t: '04:22:11', e: '[RECON] System architecture discovery initiated', lvl: 'LOW' },
                                { t: '04:23:05', e: '[CREDENTIAL_ACCESS] Attempting to read /etc/shadow', lvl: 'CRITICAL' },
                                { t: '04:24:41', e: '[PRIVILEGE_ESCALATION] Sudo NOPASSWD exploit attempt', lvl: 'HIGH' },
                            ].map(({ t, e, lvl }) => {
                                const c = lvl === 'CRITICAL' ? '#EF4444' : lvl === 'HIGH' ? '#F59E0B' : '#10B981';
                                return (
                                    <div key={t} className="flex items-start gap-4 relative z-10">
                                        <span className="text-[10px] text-slate-500 w-16 pt-1">{t}</span>
                                        <div className="w-2 h-2 mt-1.5 rounded-full border border-black" style={{ background: c, boxShadow: `0 0 10px ${c}` }} />
                                        <span className="text-slate-300 leading-relaxed">{e}</span>
                                    </div>
                                );
                            })}
                        </div>
                    </TerminalWindow>

                    {/* Live Feed */}
                    <TerminalWindow title="Live_Feed.exe" path="~/deceptishield/stream/tty" delay={0.3} className="min-h-[400px]">
                        <LiveFeed />
                    </TerminalWindow>
                </div>

                {/* RIGHT COLUMN (4/12) */}
                <div className="lg:col-span-4 flex flex-col gap-8">

                    {/* ML Score - Clean Terminal Variant */}
                    <TerminalWindow title="Threat_Analyzer" path="./ml_engine/score.py" delay={0.4}>
                        <div className="flex-1 flex flex-col items-center justify-between h-full w-full pb-4">

                            {/* Main Score Visualization */}
                            <div className="flex-1 flex flex-col items-center justify-center">
                                <ModernThreatRing score={SESSION.threatScore} />
                            </div>

                            {/* Data Vectors - Terminal Stream Style */}
                            <div className="w-full space-y-6 px-4">

                                {/* Vector 1 */}
                                <div>
                                    <div className="flex justify-between font-mono text-[10px] uppercase tracking-widest mb-3">
                                        <span className="text-slate-400">Lateral_Mvmt</span>
                                        <span className="text-white font-bold">91%</span>
                                    </div>
                                    <div className="w-full h-[2px] bg-white/[0.05] relative">
                                        <motion.div
                                            initial={{ width: 0 }} animate={{ width: '91%' }} transition={{ duration: 1, delay: 0.5 }}
                                            className="absolute top-0 left-0 h-full bg-red-500"
                                            style={{ boxShadow: '0 0 12px rgba(239,68,68,0.8)' }}
                                        />
                                        <motion.div
                                            initial={{ left: 0 }} animate={{ left: '91%' }} transition={{ duration: 1, delay: 0.5 }}
                                            className="absolute top-[-3px] w-[3px] h-[8px] bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]"
                                        />
                                    </div>
                                </div>

                                {/* Vector 2 */}
                                <div>
                                    <div className="flex justify-between font-mono text-[10px] uppercase tracking-widest mb-3">
                                        <span className="text-slate-400">Priv_Escalation</span>
                                        <span className="text-white font-bold">78%</span>
                                    </div>
                                    <div className="w-full h-[2px] bg-white/[0.05] relative">
                                        <motion.div
                                            initial={{ width: 0 }} animate={{ width: '78%' }} transition={{ duration: 1, delay: 0.6 }}
                                            className="absolute top-0 left-0 h-full bg-[#F59E0B]"
                                            style={{ boxShadow: '0 0 12px rgba(245,158,11,0.8)' }}
                                        />
                                        <motion.div
                                            initial={{ left: 0 }} animate={{ left: '78%' }} transition={{ duration: 1, delay: 0.6 }}
                                            className="absolute top-[-3px] w-[3px] h-[8px] bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]"
                                        />
                                    </div>
                                </div>

                            </div>
                        </div>
                    </TerminalWindow>

                    {/* Blockchain Forensic Button */}
                    <TerminalWindow title="Ledger_Mint" path="sepolia://smart-contract/execute" delay={0.5}>
                        <ReportButton />
                    </TerminalWindow>

                </div>
            </main>
        </div>
    );
}