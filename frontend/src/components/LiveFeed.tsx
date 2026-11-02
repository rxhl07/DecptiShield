import { useEffect, useRef } from 'react';
import { BAND_STYLE, asBand } from '../severity';

export interface LogEntry {
    id: string;
    timestamp: string;
    command: string;
    risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    score: number;
    response?: string; // AI output the attacker saw (only for commands received while the page is open)
}

interface LiveFeedProps {
    logs: LogEntry[];
    selectedId?: string | null;
    onSelect?: (id: string) => void;
}

// Live command feed for one session. Newest at the bottom, auto-scrolls.
export default function LiveFeed({ logs, selectedId = null, onSelect }: LiveFeedProps) {
    const scrollRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom whenever the logs prop updates
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTo({
                top: scrollRef.current.scrollHeight,
                behavior: 'smooth'
            });
        }
    }, [logs]);

    return (
        <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center justify-between border-b-2 border-ds-line px-[18px] py-2.5">
                <span className="ds-label">Live command feed</span>
                <span className="font-mono text-[10.5px] tracking-[0.1em] text-ds-faint">
                    {logs.length} CMD · NEWEST AT BOTTOM · CLICK A ROW FOR ITS OUTPUT
                </span>
            </div>

            {/* column headings */}
            {logs.length > 0 && (
                <div className="flex items-center gap-3 border-b border-ds-line pl-[18px] pr-[14px] py-1.5 font-mono text-[10px] font-bold tracking-[0.16em] text-ds-faint">
                    <span className="w-[64px] shrink-0">TIME</span>
                    <span className="flex-1">COMMAND</span>
                    <span className="w-[104px] shrink-0 text-center">SEVERITY</span>
                    <span className="w-[42px] shrink-0 text-right">SCORE</span>
                </div>
            )}

            <div ref={scrollRef} className="ds-scroll min-h-[160px] flex-1 overflow-y-auto font-mono">
                {logs.length === 0 && (
                    <div className="flex h-full flex-col items-center justify-center gap-3.5 px-6 py-12 text-center">
                        <div className="h-[22px] w-[22px] animate-[ds-pulse_2.4s_ease-in-out_infinite] border-2 border-ds-line" />
                        <div className="text-[13px] uppercase tracking-[0.2em] text-ds-dim">Awaiting contact</div>
                        <div className="text-[11px] text-ds-faint">Commands typed by the attacker will appear here as they arrive</div>
                    </div>
                )}

                {logs.map((entry) => {
                    const band = asBand(entry.risk);
                    const st = BAND_STYLE[band];
                    const crit = band === 'CRITICAL';
                    const selected = entry.id === selectedId;
                    const rowCls = crit
                        ? 'bg-ds-crit text-ds-crit-ink border-l-ds-crit-ink'
                        : selected
                            ? `bg-ds-sel text-ds-ink border-l-ds-acc`
                            : `text-ds-ink hover:bg-ds-sel ${st.mark}`;
                    return (
                        <div
                            key={entry.id}
                            onClick={onSelect ? () => onSelect(entry.id) : undefined}
                            className={`flex items-center gap-3 border-b border-l-4 border-b-ds-hair pl-[14px] pr-[14px] animate-[ds-row-in_120ms_ease-out] ${crit ? 'py-3' : 'py-2.5'} ${onSelect ? 'cursor-pointer' : ''} ${rowCls} ${selected && crit ? 'outline-2 outline-offset-[-2px] outline-ds-acc' : ''}`}
                        >
                            <span className={`w-[64px] shrink-0 text-[11.5px] ${crit ? 'text-ds-crit-dim' : 'text-ds-faint'}`}>
                                {entry.timestamp.slice(11)}
                            </span>
                            <span className={`min-w-0 flex-1 truncate ${crit ? 'text-[15px] font-bold' : 'text-[13.5px] font-medium'}`}>
                                {entry.command}
                            </span>
                            <span
                                className={`inline-flex w-[104px] shrink-0 items-center justify-center gap-1.5 border px-[7px] py-[3px] text-[10.5px] font-bold tracking-[0.08em] ${crit ? 'border-ds-crit-ink bg-ds-crit-ink text-ds-crit' : st.chip}`}
                            >
                                <span>{st.glyph}</span>
                                <span>{band}</span>
                            </span>
                            <span className="w-[42px] shrink-0 text-right text-[13px] font-bold">{entry.score}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
