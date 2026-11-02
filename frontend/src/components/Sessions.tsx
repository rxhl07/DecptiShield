import { useNavigate } from 'react-router-dom';
import TopNav from './TopNav';
import { useSessionList } from '../hooks/useSessionList';
import { BAND_STYLE, bandOf } from '../severity';

function fmtTime(iso: string) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function Sessions() {
    const navigate = useNavigate();
    const { sessions, backendDown, backendUrl } = useSessionList();

    const activeCount = sessions.filter((s) => s.status === 'active').length;

    return (
        <div className="min-h-screen w-full bg-ds-bg text-ds-ink">
            <TopNav />

            <main className="mx-auto max-w-[1600px] px-6 py-10 sm:px-9">
                {/* Page header */}
                <div className="mb-8 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <p className="ds-label mb-2">SOC dashboard</p>
                        <h1 className="ds-display m-0 text-[30px] leading-[0.95] sm:text-[40px]">Intercepted sessions</h1>
                        <p className="mt-3 max-w-[60ch] text-[15px] leading-relaxed text-ds-dim">
                            Each row is one attacker connected to the honeypot. Click a row to open its dashboard.
                        </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2.5 border-2 border-ds-acc px-3 py-2">
                        <span className={`h-2 w-2 bg-ds-acc ${activeCount > 0 ? 'animate-[ds-pulse_1.6s_steps(1)_infinite]' : ''}`} />
                        <span className="font-mono text-[12px] font-bold tracking-[0.14em] text-ds-acc">{activeCount} ACTIVE</span>
                        <span className="font-mono text-[12px] text-ds-dim">/ {sessions.length} TOTAL</span>
                    </div>
                </div>

                {/* Session table */}
                <div className="border-2 border-ds-line">
                    <div className="flex items-center justify-between border-b-2 border-ds-line bg-ds-panel px-[18px] py-2.5">
                        <span className="ds-label">Sessions</span>
                        <span className="font-mono text-[11px] tracking-[0.1em] text-ds-faint">ACTIVE FIRST · NEWEST FIRST</span>
                    </div>

                    {sessions.length === 0 ? (
                        <div className="flex flex-col items-center justify-center gap-3.5 px-6 py-20 text-center">
                            <div className="h-[22px] w-[22px] animate-[ds-pulse_2.4s_ease-in-out_infinite] border-2 border-ds-line" />
                            <div className="font-mono text-[14px] uppercase tracking-[0.2em] text-ds-dim">No current sessions</div>
                            {backendDown ? (
                                <div className="font-mono text-[11px] text-ds-crit">Backend unreachable at {backendUrl}</div>
                            ) : (
                                <div className="font-mono text-[11px] text-ds-faint">
                                    Waiting for an attacker on SSH port 2222 or the attack simulator
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="ds-scroll overflow-x-auto">
                            <table className="w-full min-w-[760px] border-collapse font-mono">
                                <thead>
                                    <tr className="text-left text-[10.5px] font-bold uppercase tracking-[0.16em] text-ds-dim">
                                        <th className="border-b border-ds-line py-2.5 pl-[18px] pr-3 font-bold">Session</th>
                                        <th className="border-b border-ds-line px-3 py-2.5 font-bold">Attacker IP</th>
                                        <th className="border-b border-ds-line px-3 py-2.5 font-bold">Started</th>
                                        <th className="border-b border-ds-line px-3 py-2.5 font-bold">Status</th>
                                        <th className="border-b border-ds-line px-3 py-2.5 font-bold">Avg threat score</th>
                                        <th className="border-b border-ds-line px-3 py-2.5 text-right font-bold">Commands</th>
                                        <th className="border-b border-ds-line py-2.5 pl-3 pr-[18px]" />
                                    </tr>
                                </thead>
                                <tbody>
                                    {sessions.map((s) => {
                                        const active = s.status === 'active';
                                        const band = bandOf(s.threatScore);
                                        const st = BAND_STYLE[band];
                                        return (
                                            <tr
                                                key={s.sessionId}
                                                onClick={() => navigate(`/dashboard/${encodeURIComponent(s.sessionId)}`)}
                                                className="group cursor-pointer transition-colors hover:bg-ds-sel"
                                            >
                                                <td className={`border-b border-l-4 border-b-ds-hair py-3.5 pl-[14px] pr-3 group-hover:border-l-ds-acc ${active ? 'border-l-ds-acc/60' : 'border-l-transparent'}`}>
                                                    <span className={`text-[13px] font-bold tracking-[0.02em] ${active ? 'text-ds-ink' : 'text-ds-dim'}`}>{s.sessionId}</span>
                                                </td>
                                                <td className="border-b border-ds-hair px-3 py-3.5 text-[13px] text-ds-soft">{s.ip}</td>
                                                <td className="border-b border-ds-hair px-3 py-3.5 text-[12px] text-ds-dim">{fmtTime(s.startTime)}</td>
                                                <td className="border-b border-ds-hair px-3 py-3.5">
                                                    <span className={`text-[11px] font-bold tracking-[0.12em] ${active ? 'text-ds-acc' : 'text-ds-faint'}`}>
                                                        {active ? '● ACTIVE' : '■ CLOSED'}
                                                    </span>
                                                </td>
                                                <td className="border-b border-ds-hair px-3 py-3.5">
                                                    <span className={`inline-flex items-center gap-2 border px-[7px] py-[3px] text-[11px] font-bold tracking-[0.08em] ${st.chip}`}>
                                                        <span>{st.glyph}</span>
                                                        <span>{band} {s.threatScore}</span>
                                                    </span>
                                                </td>
                                                <td className="border-b border-ds-hair px-3 py-3.5 text-right text-[13px] text-ds-soft">{s.commandCount}</td>
                                                <td className="border-b border-ds-hair py-3.5 pl-3 pr-[18px] text-right text-[11px] font-bold tracking-[0.12em] text-ds-faint group-hover:text-ds-acc">
                                                    OPEN →
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}
