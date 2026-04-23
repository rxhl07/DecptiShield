import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link2, CheckCircle, AlertTriangle, FileCode2, Cpu } from 'lucide-react';

export default function ReportButton() {
    const [phase, setPhase] = useState<'idle' | 'loading' | 'done'>('idle');

    const handleGenerate = () => {
        setPhase('loading');
        setTimeout(() => setPhase('done'), 3500); // Mocks the API call delay
    };

    return (
        <div className="flex flex-col h-full relative">
            <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-red-500 to-transparent opacity-50" />

            <div className="flex items-center gap-3 mb-6">
                <Link2 size={16} className="text-[#EF4444]" />
                <span className="text-xs font-black tracking-widest uppercase text-white">Blockchain Forensics</span>
                <span className="ml-auto font-mono text-[9px] px-2 py-1 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-bold tracking-widest">SEPOLIA L1</span>
            </div>

            <div className="flex items-start gap-4 p-5 rounded-xl mb-6 bg-red-500/[0.05] border border-red-500/20">
                <AlertTriangle size={16} className="text-[#EF4444] shrink-0" />
                <p className="font-mono text-xs leading-relaxed text-slate-400">
                    Compile incident actions into a SHA-256 hash tree. Interplanetary File System (IPFS) pinning ensures immutability.
                </p>
            </div>

            <button
                disabled={phase !== 'idle'}
                onClick={handleGenerate}
                className="w-full px-6 py-5 rounded-xl font-black text-sm tracking-widest uppercase transition-all duration-300 flex items-center justify-center gap-3 disabled:opacity-80"
                style={{
                    background: phase === 'loading' ? 'rgba(239,68,68,0.1)' : phase === 'done' ? 'rgba(16,185,129,0.15)' : '#EF4444',
                    border: `1px solid ${phase === 'loading' ? 'rgba(239,68,68,0.3)' : phase === 'done' ? 'rgba(16,185,129,0.5)' : '#EF4444'}`,
                    color: phase === 'done' ? '#10B981' : phase === 'loading' ? '#EF4444' : '#fff',
                }}
            >
                {phase === 'loading' ? (
                    <><Cpu size={18} className="animate-pulse" /> ENCRYPTING LEDGER...</>
                ) : phase === 'done' ? (
                    <><CheckCircle size={18} /> MINTED TO SEPOLIA</>
                ) : (
                    <><FileCode2 size={18} /> COMPILE EVIDENCE</>
                )}
            </button>

            {/* Done State Result */}
            <AnimatePresence>
                {phase === 'done' && (
                    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="mt-6 p-5 rounded-xl border border-emerald-500/30 bg-[#050505]">
                        <p className="font-mono text-[10px] mb-2 text-slate-500 tracking-widest">IPFS CID</p>
                        <code className="block w-full truncate font-mono text-xs text-slate-300 p-3 bg-white/5 rounded-lg mb-4">QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG</code>
                        <p className="font-mono text-[10px] mb-2 text-slate-500 tracking-widest">TRANSACTION HASH</p>
                        <code className="block w-full truncate font-mono text-xs text-slate-300 p-3 bg-white/5 rounded-lg">0x9a3f...82bc</code>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}