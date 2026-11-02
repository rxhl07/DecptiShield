import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import TopNav from './TopNav';
import LiveFeed, { type LogEntry } from './LiveFeed';
import ReportButton from './ReportButton';
import { socket } from '../socket';
import { useSessionList } from '../hooks/useSessionList';
import { BAND_RANGE, BAND_STYLE, asBand, bandOf, type Band } from '../severity';

// Event shapes (sessionId may be missing on legacy/untagged events)
interface FeedEvent { sessionId?: string; command: string; response?: string; threatScore: number; severity: string; }
interface ProfileEvent { sessionId?: string; ip: string; geo: string; isp: string; type: string; org?: string; }
interface SessionEvent { sessionId?: string; status?: 'active' | 'closed'; }
type Profile = { ip: string; geo: string; isp: string; type: string; org?: string };

const BANDS_DESC: Band[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const BANDS_ASC: Band[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// Remount the dashboard per session so no state (profile, logs, selection) carries over
// when switching sessions from the sidebar.
export default function DashboardRoute() {
    const { sessionId } = useParams();
    return <Dashboard key={sessionId ?? '__all__'} />;
}

function Dashboard() {
    // When sessionId is present, the dashboard shows ONLY that session.
    // Without it (/dashboard), behaviour is unchanged: all events.
    const { sessionId } = useParams();
    const navigate = useNavigate();
    const [threatScore, setThreatScore] = useState(0);
    const [profile, setProfile] = useState<Profile>({ ip: 'AWAITING...', geo: 'UNKNOWN', isp: 'WAITING', type: 'WAITING FOR CONNECTION' });
    const [sessionLogs, setSessionLogs] = useState<LogEntry[]>([]);
    const [sessionStatus, setSessionStatus] = useState<'active' | 'closed'>('active');
    const [notFound, setNotFound] = useState(false);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const { sessions } = useSessionList();

    useEffect(() => {
        let cancelled = false;

        // Scoped mode: load this session's history (commands, score, profile, status)
        const loadSession = () => {
            if (!sessionId) return;
            fetch(`http://localhost:8000/api/sessions/${encodeURIComponent(sessionId)}`)
                .then((res) => {
                    if (res.status === 404) {
                        if (!cancelled) setNotFound(true);
                        return null;
                    }
                    return res.json();
                })
                .then((data) => {
                    if (!data || cancelled) return;
                    setNotFound(false);
                    if (data.profile && data.profile.ip) setProfile(data.profile);
                    if (Array.isArray(data.logs)) setSessionLogs(data.logs);
                    if (typeof data.threatScore === 'number') setThreatScore(data.threatScore);
                    if (data.status === 'active' || data.status === 'closed') setSessionStatus(data.status);
                })
                .catch(() => { });
        };

        if (sessionId) {
            loadSession();
        } else {
            // Fetch current active profile immediately on component mount
            fetch('http://localhost:8000/api/profile')
                .then((res) => res.json())
                .then((data) => {
                    if (data && data.ip) {
                        setProfile(data);
                    }
                })
                .catch(() => { });
        }

        const onProfileUpdate = (data: ProfileEvent) => {
            if (sessionId) {
                if (!data || data.sessionId !== sessionId) return;
                setProfile(data);
                return;
            }
            setProfile(data);
            setSessionLogs([]);
        };

        const onLiveFeedUpdate = (data: FeedEvent) => {
            if (sessionId && (!data || data.sessionId !== sessionId)) return;
            setThreatScore(data.threatScore);

            const newLog: LogEntry = {
                id: data.sessionId + '-' + Date.now(),
                timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
                command: data.command,
                risk: asBand(data.severity),
                score: data.threatScore,
                response: data.response,
            };
            setSessionLogs((prev) => [...prev, newLog]);
        };

        const onSessionUpdate = (data: SessionEvent) => {
            if (!sessionId || !data || data.sessionId !== sessionId) return;
            setNotFound(false);
            if (data.status === 'active' || data.status === 'closed') setSessionStatus(data.status);
        };

        socket.on('session_profile_update', onProfileUpdate);
        socket.on('live_feed_update', onLiveFeedUpdate);
        socket.on('session_update', onSessionUpdate);
        // Re-sync scoped history after a reconnect
        socket.on('connect', loadSession);
        // The attacker terminal disconnects the shared socket when it unmounts
        // (only if fully shut down; calling connect() while still connecting sends a duplicate CONNECT)
        if (!socket.active) socket.connect();

        return () => {
            cancelled = true;
            socket.off('session_profile_update', onProfileUpdate);
            socket.off('live_feed_update', onLiveFeedUpdate);
            socket.off('session_update', onSessionUpdate);
            socket.off('connect', loadSession);
        };
    }, [sessionId]);

    const isClosed = !!sessionId && sessionStatus === 'closed';

    // ---- derived, display-only values ----
    const waiting = profile.ip.includes('AWAIT');
    const hasData = sessionLogs.length > 0;
    const band = bandOf(threatScore);
    const bandSt = BAND_STYLE[band];
    const selected = sessionLogs.find((l) => l.id === selectedId) ?? sessionLogs[sessionLogs.length - 1];
    const following = !selectedId || !sessionLogs.some((l) => l.id === selectedId);
    const trace = sessionLogs.slice(-18);
    const firstInBand = new Map<Band, LogEntry>();
    for (const l of sessionLogs) {
        const b = asBand(l.risk);
        if (!firstInBand.has(b)) firstInBand.set(b, l);
    }
    const notReached = BANDS_ASC.filter((b) => !firstInBand.has(b));
    const activeCount = sessions.filter((s) => s.status === 'active').length;

    const toggleSelect = (id: string) => setSelectedId((cur) => (cur === id ? null : id));

    return (
        <div className="min-h-screen w-full bg-ds-bg text-ds-ink">
            <TopNav />

            <div className="grid grid-cols-1 xl:h-[calc(100vh-54px)] xl:grid-cols-[264px_minmax(0,1fr)_348px] xl:overflow-hidden">

                {/* ───────── LEFT: sessions ───────── */}
                <aside className="flex flex-col border-b-2 border-ds-line xl:min-h-0 xl:border-b-0 xl:border-r-2">
                    <div className="flex items-center justify-between border-b-2 border-ds-line px-[14px] py-2.5">
                        <button onClick={() => navigate('/sessions')} className="ds-label cursor-pointer hover:text-ds-ink">
                            ← Sessions
                        </button>
                        <span className="font-mono text-[11px] font-bold tracking-[0.08em] text-ds-acc">
                            {activeCount} ACTIVE / {sessions.length}
                        </span>
                    </div>
                    <div className="ds-scroll max-h-[260px] overflow-y-auto xl:max-h-none xl:flex-1">
                        {sessions.length === 0 && (
                            <div className="px-[14px] py-6 font-mono text-[11px] text-ds-faint">No current sessions</div>
                        )}
                        {sessions.map((s) => {
                            const on = s.sessionId === sessionId;
                            const live = s.status === 'active';
                            const sb = bandOf(s.threatScore);
                            const sst = BAND_STYLE[sb];
                            return (
                                <button
                                    key={s.sessionId}
                                    onClick={() => navigate(`/dashboard/${encodeURIComponent(s.sessionId)}`)}
                                    className={`block w-full cursor-pointer border-b border-l-4 border-b-ds-hair px-[14px] py-3 text-left transition-colors ${on ? 'border-l-ds-acc bg-ds-sel' : 'border-l-transparent hover:bg-ds-sel'}`}
                                >
                                    <div className="mb-1.5 flex items-center justify-between">
                                        <span className={`font-mono text-[12.5px] font-bold tracking-[0.02em] ${on ? 'text-ds-ink' : 'text-ds-soft'}`}>{s.sessionId}</span>
                                        <span className={`font-mono text-[10px] font-bold tracking-[0.1em] ${live ? 'text-ds-acc' : 'text-ds-faint'}`}>
                                            {live ? '● ACTIVE' : '■ CLOSED'}
                                        </span>
                                    </div>
                                    <div className="mb-2 font-mono text-[11px] text-ds-dim">{s.ip} · {s.source}</div>
                                    <div className="flex items-center gap-2">
                                        <span className={`inline-flex items-center gap-1.5 border px-1.5 py-[2px] font-mono text-[10px] font-bold tracking-[0.06em] ${sst.chip}`}>
                                            {sst.glyph} {s.threatScore}
                                        </span>
                                        <span className="font-mono text-[10px] text-ds-faint">{s.commandCount} CMD</span>
                                    </div>
                                </button>
                            );
                        })}
                    </div>
                    <div className="hidden border-t-2 border-ds-line px-[14px] py-3 xl:block">
                        <div className="ds-label mb-1.5">Honeypot</div>
                        <div className="font-mono text-[11px] leading-relaxed text-ds-dim">
                            SSH on port 2222<br />Poses as ubuntu@prod-db-01
                        </div>
                    </div>
                </aside>

                {/* ───────── CENTER: adversary, feed, response ───────── */}
                <section className="flex flex-col border-b-2 border-ds-line xl:min-h-0 xl:border-b-0 xl:border-r-2">
                    {/* adversary identity */}
                    <div className="border-b-2 border-ds-line bg-ds-panel px-[18px] pb-4 pt-3.5">
                        <div className="flex items-start justify-between gap-5">
                            <div className="min-w-0">
                                <div className="ds-label mb-1.5">
                                    {sessionId ? <>Adversary · session <span className="text-ds-ink">{sessionId}</span></> : 'All sessions (unfiltered view)'}
                                </div>
                                <div
                                    title={waiting ? undefined : profile.geo}
                                    className={`ds-display truncate text-[30px] leading-[1.05] ${waiting ? 'text-ds-ghost' : isClosed ? 'text-ds-dim' : 'text-ds-crit'}`}
                                >
                                    {waiting ? 'Awaiting attacker' : profile.geo}
                                </div>
                            </div>
                            {sessionId && (() => {
                                const dead = isClosed || notFound;
                                return (
                                    <div className={`flex shrink-0 items-center gap-2 border-2 px-3 py-1.5 ${dead ? 'border-ds-faint' : 'border-ds-acc'}`}>
                                        <span className={`h-2 w-2 ${dead ? 'bg-ds-faint' : 'animate-[ds-pulse_1.6s_steps(1)_infinite] bg-ds-acc'}`} />
                                        <span className={`font-mono text-[11px] font-bold tracking-[0.14em] ${dead ? 'text-ds-dim' : 'text-ds-acc'}`}>
                                            {notFound ? 'NOT FOUND' : isClosed ? 'SESSION CLOSED' : 'LIVE'}
                                        </span>
                                    </div>
                                );
                            })()}
                        </div>
                        <div className="mt-3.5 grid grid-cols-2 gap-px bg-ds-line md:grid-cols-4">
                            {[
                                { k: 'IP address', v: profile.ip },
                                { k: 'ISP', v: profile.isp },
                                { k: 'Organisation', v: profile.org || '—' },
                                { k: 'Connection', v: profile.type },
                            ].map((c) => (
                                <div key={c.k} className="min-w-0 bg-ds-panel px-3 py-2">
                                    <div className="mb-1 font-mono text-[10px] font-bold uppercase tracking-[0.14em] text-ds-faint">{c.k}</div>
                                    <div title={c.v} className={`truncate font-mono text-[13px] ${waiting ? 'text-ds-faint' : 'text-ds-ink'}`}>{c.v}</div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {sessionId && notFound && (
                        <div className="border-b-2 border-ds-line bg-ds-high px-[18px] py-2 font-mono text-[12px] font-bold tracking-[0.06em] text-ds-high-ink">
                            SESSION {sessionId} NOT FOUND. IT MAY HAVE ENDED BEFORE A BACKEND RESTART.
                        </div>
                    )}

                    {/* feed */}
                    <div className="flex max-h-[520px] min-h-[260px] flex-col xl:max-h-none xl:min-h-0 xl:flex-1">
                        <LiveFeed logs={sessionLogs} selectedId={following ? null : selectedId} onSelect={toggleSelect} />
                    </div>

                    {/* what the attacker saw */}
                    <div className="flex h-[210px] shrink-0 flex-col border-t-2 border-ds-line bg-ds-panel">
                        <div className="flex items-center justify-between border-b border-ds-line px-[18px] py-2">
                            <span className="ds-label">What the attacker saw: AI response</span>
                            <span className="font-mono text-[10.5px] tracking-[0.1em] text-ds-faint">
                                {!selected ? 'NO COMMANDS YET' : following ? 'FOLLOWING LATEST' : 'SELECTED ROW · CLICK AGAIN TO FOLLOW LATEST'}
                            </span>
                        </div>
                        <div className="ds-scroll flex-1 overflow-y-auto px-[18px] pb-4 pt-3 font-mono">
                            {!selected ? (
                                <div className="text-[12.5px] text-ds-faint">Select a command in the feed to see the output the attacker was shown.</div>
                            ) : (
                                <>
                                    <div className="mb-2.5 flex flex-wrap items-center gap-2.5 text-[13px]">
                                        <span className="text-ds-faint">ubuntu@prod-db-01:~$</span>
                                        <span className="font-bold text-ds-ink">{selected.command}</span>
                                        <span className={`border px-1.5 py-[2px] text-[10px] font-bold tracking-[0.08em] ${BAND_STYLE[asBand(selected.risk)].chip}`}>
                                            {asBand(selected.risk)} {selected.score}
                                        </span>
                                    </div>
                                    <div className="whitespace-pre-wrap text-[12.5px] leading-relaxed text-ds-soft">
                                        {selected.response === undefined
                                            ? <span className="text-ds-faint">Output not captured: this command ran before the dashboard was opened.</span>
                                            : selected.response === '[silent execution]' || selected.response === ''
                                                ? <span className="text-ds-faint">No output. The honeypot ran this command silently (e.g. cd, touch, mkdir, rm).</span>
                                                : selected.response}
                                    </div>
                                </>
                            )}
                        </div>
                    </div>
                </section>

                {/* ───────── RIGHT: threat, escalation, export ───────── */}
                <aside className="flex flex-col xl:min-h-0">
                    {/* threat level */}
                    <div className="border-b-2 border-ds-line">
                        <div className="flex items-center justify-between border-b-2 border-ds-line px-[14px] py-2.5">
                            <span className="ds-label">Threat level</span>
                            <span className="font-mono text-[10.5px] tracking-[0.08em] text-ds-faint">SESSION AVERAGE · 0–100</span>
                        </div>
                        <div className="flex gap-3.5 px-[14px] pb-3.5 pt-3">
                            <div className="min-w-0 flex-1">
                                <div className={`ds-display text-[96px] leading-[0.82] tracking-[-0.04em] ${!hasData ? 'text-ds-ghost' : band === 'LOW' ? 'text-ds-ink' : bandSt.text}`}>
                                    {hasData ? threatScore : '–'}
                                </div>
                                <div className={`mt-2.5 inline-block border-2 px-2 py-1 font-mono text-[12px] font-bold tracking-[0.14em] ${hasData ? bandSt.chip : 'border-ds-ghost text-ds-faint'}`}>
                                    {hasData ? band : 'NO DATA'}
                                </div>
                                <div className="mt-3.5 flex h-[34px] items-end gap-0.5">
                                    {trace.map((l) => (
                                        <div
                                            key={l.id}
                                            title={`${l.command} · ${l.score}`}
                                            className={`w-[5px] ${BAND_STYLE[asBand(l.risk)].traceBg}`}
                                            style={{ height: `${Math.max(6, Math.round(l.score * 0.34))}px` }}
                                        />
                                    ))}
                                </div>
                                <div className="mt-1.5 font-mono text-[10px] tracking-[0.1em] text-ds-faint">
                                    SCORE TRACE · LAST {trace.length} COMMANDS
                                </div>
                            </div>
                            <div className="flex w-[104px] flex-col gap-0.5">
                                {BANDS_DESC.map((b) => {
                                    const on = hasData && b === band;
                                    const st = BAND_STYLE[b];
                                    return (
                                        <div
                                            key={b}
                                            className={`flex flex-1 flex-col justify-between border-l-4 px-1.5 py-1 ${on ? `${b === 'LOW' ? 'bg-ds-sel text-ds-ink' : st.chip} border-l-ds-ink` : `${st.bandBg} ${st.mark} ${st.text}`}`}
                                            style={{ flexGrow: b === 'LOW' ? 30 : b === 'CRITICAL' ? 22 : 24 }}
                                        >
                                            <span className="font-mono text-[9.5px] font-bold tracking-[0.06em]">{st.glyph} {b}</span>
                                            <span className="font-mono text-[9.5px] opacity-80">{BAND_RANGE[b]}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>

                    {/* escalation path */}
                    <div className="flex flex-col border-b-2 border-ds-line xl:min-h-0 xl:flex-1">
                        <div className="border-b-2 border-ds-line px-[14px] py-2.5">
                            <div className="ds-label">Escalation path</div>
                            <div className="mt-1 font-mono text-[10.5px] tracking-[0.04em] text-ds-faint">
                                COMMAND AT WHICH THE SESSION FIRST REACHED EACH BAND
                            </div>
                        </div>
                        <div className="ds-scroll overflow-y-auto xl:flex-1">
                            {/* Map keeps insertion order = chronological order of first reaching each band */}
                            {[...firstInBand.entries()].map(([b, l]) => {
                                const st = BAND_STYLE[b];
                                return (
                                    <div key={b} className="flex gap-2.5 border-b border-ds-hair px-[14px] py-2.5">
                                        <div className={`w-[3px] shrink-0 ${st.traceBg}`} />
                                        <div className="min-w-0 flex-1">
                                            <div className="mb-1 flex justify-between gap-2 font-mono text-[10.5px]">
                                                <span className={`font-bold tracking-[0.08em] ${st.text}`}>{st.glyph} {b}</span>
                                                <span className="text-ds-faint">{l.timestamp.slice(11)}</span>
                                            </div>
                                            <div title={l.command} className="truncate font-mono text-[12px] text-ds-soft">{l.command}</div>
                                        </div>
                                    </div>
                                );
                            })}
                            {hasData && notReached.length > 0 && (
                                <div className="px-[14px] py-2.5 font-mono text-[10.5px] tracking-[0.06em] text-ds-faint">
                                    NOT YET REACHED: {notReached.join(' · ')}
                                </div>
                            )}
                            {!hasData && (
                                <div className="px-[14px] py-4 font-mono text-[11px] text-ds-faint">No commands yet.</div>
                            )}
                        </div>
                    </div>

                    {/* export */}
                    <div className="px-[14px] py-3.5">
                        <ReportButton logs={sessionLogs} profile={profile} />
                    </div>
                </aside>
            </div>
        </div>
    );
}
