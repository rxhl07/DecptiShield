import { useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useMotionTemplate } from 'framer-motion';
import { Shield, Terminal, LayoutDashboard, Zap, Lock, Eye, ChevronRight } from 'lucide-react';
import { useMousePosition } from '../hooks/useMousePosition'; // You can remove this import if you aren't using the mouse hook yet

const FEATURES = [
    {
        icon: Zap,
        label: 'AI Deception Engine',
        desc: 'Dynamic honeypots that adapt in real-time to attacker behavior patterns using localized reinforcement learning.',
    },
    {
        icon: Eye,
        label: 'Threat Intelligence',
        desc: 'ML-scored threat feeds with live attacker profiling, TTP mapping, and global IP reputation scoring.',
    },
    {
        icon: Lock,
        label: 'Blockchain Forensics',
        desc: 'Immutable evidence ledgers minted to Sepolia for legal-grade audit trails via localized IPFS pinning.',
    },
];

export default function Landing() {
    const navigate = useNavigate();

    return (
        <div className="relative min-h-screen w-full flex flex-col">
            <div className="app-bg" />

            {/* Nav bar */}
            <motion.nav
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, ease: 'easeOut' }}
                className="relative z-20 flex items-center justify-between px-6 md:px-10 py-5 border-b border-white/5 bg-black/40 backdrop-blur-xl"
            >
                <div className="flex items-center gap-3 group cursor-pointer">
                    <div className="relative w-9 h-9 rounded-xl flex items-center justify-center bg-[#2D5BFF]/10 border border-[#2D5BFF]/30">
                        <Shield size={18} className="text-[#2D5BFF] relative z-10" />
                    </div>
                    <span className="text-sm font-black tracking-[0.2em] uppercase text-white">
                        DeceptiShield
                    </span>
                </div>
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="font-mono text-[10px] sm:text-xs text-emerald-400 font-medium uppercase tracking-widest">System Intact</span>
                </div>
            </motion.nav>

            {/* Hero */}
            <main className="relative z-10 flex flex-col items-center justify-center flex-1 px-4 py-24 text-center">

                <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.2 }} className="mb-8">
                    <span className="inline-flex items-center gap-2 font-mono text-[10px] sm:text-xs px-5 py-2.5 rounded-full bg-[#2D5BFF]/10 border border-[#2D5BFF]/20 text-[#2D5BFF] tracking-widest uppercase">
                        <Zap size={14} /> NEXT-GEN ACTIVE DEFENSE PLATFORM · v3.0
                    </span>
                </motion.div>

                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, delay: 0.3 }} className="relative max-w-5xl mx-auto">
                    <h1 className="font-black uppercase text-white pb-4 tracking-tighter" style={{ fontSize: 'clamp(4rem, 10vw, 8rem)', lineHeight: 0.9 }}>
                        Deceive.<br />Detect.<br />Destroy.
                    </h1>
                </motion.div>

                <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.8, delay: 0.5 }} className="mt-8 max-w-2xl text-base sm:text-lg leading-relaxed text-slate-400 font-medium">
                    DeceptiShield deploys intelligent dynamic honeypots that adapt to adversary TTPs in real-time. Actionable threat feeds. Immutable <span className="text-[#10B981] font-bold">on-chain forensics</span>.
                </motion.p>

                {/* CTA Buttons */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.7 }} className="mt-14 flex flex-col sm:flex-row items-center justify-center gap-5">
                    <button className="cyber-btn-ghost w-full sm:w-auto flex items-center justify-center gap-3 px-8 py-4 rounded-xl font-bold text-sm tracking-[0.15em] uppercase" onClick={() => navigate('/attacker')}>
                        <Terminal size={18} /> Launch Attack Sim
                    </button>
                    <button className="cyber-btn-primary w-full sm:w-auto flex items-center justify-center gap-3 px-8 py-4 rounded-xl font-bold text-sm tracking-[0.15em] uppercase" onClick={() => navigate('/dashboard')}>
                        <LayoutDashboard size={18} /> SOC Command Center
                    </button>
                </motion.div>

                {/* Feature Cards row */}
                <div className="mt-32 grid grid-cols-1 md:grid-cols-3 gap-8 w-full max-w-[1200px]">
                    {FEATURES.map(({ icon: Icon, label, desc }, i) => (
                        <motion.div key={label} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.9 + i * 0.15 }} className="premium-glass rounded-3xl p-8 text-left">
                            <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-6 bg-[#2D5BFF]/10 border border-[#2D5BFF]/30">
                                <Icon size={22} className="text-[#2D5BFF]" />
                            </div>
                            <h3 className="font-black text-sm md:text-base tracking-widest uppercase mb-3 text-white">{label}</h3>
                            <p className="text-xs md:text-sm leading-relaxed text-slate-400 font-medium">{desc}</p>
                        </motion.div>
                    ))}
                </div>
            </main>
        </div>
    );
}