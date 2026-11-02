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
            <div className="flex items-baseline justify-between px-6 pb-3 pt-5">
                <span className="ds-label">Live command feed</span>
                <span className="font-mono text-[11px] text-ds-faint">
                    {logs.length} {logs.length === 1 ? 'command' : 'commands'}
                </span>
            </div>

            {logs.length > 0 && (
                <div className="flex items-center gap-4 border-b border-ds-line px-6 pb-2 font-mono text-[10px] font-bold tracking-[0.16em] text-ds-faint">
                    <span className="w-[64px] shrink-0">TIME</span>
                    <span className="flex-1">COMMAND</span>
                    <span className="w-[92px] shrink-0 text-center">SEVERITY</span>
                    <span className="w-[96px] shrink-0 text-right" title="Session's average threat score after this command">SESSION AVG</span>
                </div>
            )}

            <div ref={scrollRef} className="ds-scroll min-h-[160px] flex-1 overflow-y-auto font-mono">
                {logs.length === 0 && (
                    <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-12 text-center">
                        <div className="h-[18px] w-[18px] animate-[ds-pulse_2.4s_ease-in-out_infinite] border-2 border-ds-line" />
                        <div className="text-[13px] uppercase tracking-[0.2em] text-ds-dim">Awaiting contact</div>
                        <div className="text-[11.5px] text-ds-faint">Commands typed by the attacker will appear here</div>
                    </div>
                )}

                {logs.map((entry) => {
                    const band = asBand(entry.risk);
                    const st = BAND_STYLE[band];
                    const crit = band === 'CRITICAL';
                    const selected = entry.id === selectedId;
                    const rowCls = crit
                        ? 'bg-ds-crit text-ds-crit-ink'
                        : selected
                            ? 'bg-ds-sel text-ds-ink'
                            : 'text-ds-ink hover:bg-ds-sel/70';
                    return (
                        <div
                            key={entry.id}
                            onClick={onSelect ? () => onSelect(entry.id) : undefined}
                            className={`flex items-center gap-4 border-b border-l-2 border-b-ds-hair py-3 pl-[22px] pr-6 animate-[ds-row-in_120ms_ease-out] ${onSelect ? 'cursor-pointer' : ''} ${rowCls} ${selected ? 'border-l-ds-acc' : 'border-l-transparent'}`}
                        >
                            <span className={`w-[64px] shrink-0 text-[11.5px] ${crit ? 'text-ds-crit-dim' : 'text-ds-faint'}`}>
                                {entry.timestamp.slice(11)}
                            </span>
                            <span className={`min-w-0 flex-1 truncate text-[13.5px] ${crit ? 'font-bold' : 'font-medium'}`}>
                                {entry.command}
                            </span>
                            <span
                                className={`w-[92px] shrink-0 border py-[3px] text-center text-[10.5px] font-bold tracking-[0.1em] ${crit ? 'border-ds-crit-ink/60 text-ds-crit-ink' : st.outline}`}
                            >
                                {band}
                            </span>
                            <span className={`w-[96px] shrink-0 text-right text-[13px] font-bold ${crit ? '' : 'text-ds-soft'}`}>{entry.score}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
