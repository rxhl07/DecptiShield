import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import TopNav from './TopNav';
import LiveFeed, { type LogEntry } from './LiveFeed';
import ReportButton from './ReportButton';
import { socket } from '../socket';
import { useSessionList } from '../hooks/useSessionList';
import { BAND_STYLE, asBand, bandOf, type Band } from '../severity';
import { explainCommand } from '../commandExplainer';

// Event shapes (sessionId may be missing on legacy/untagged events)
interface FeedEvent { sessionId?: string; command: string; response?: string; threatScore: number; severity: string; }
interface ProfileEvent { sessionId?: string; ip: string; geo: string; isp: string; type: string; org?: string; }
interface SessionEvent { sessionId?: string; status?: 'active' | 'closed'; }
type Profile = { ip: string; geo: string; isp: string; type: string; org?: string };

// 0-100 scale segments, matching the backend thresholds
const SCALE: { band: Band; from: number; to: number; label: string }[] = [
    { band: 'LOW', from: 0, to: 30, label: 'LOW' },
    { band: 'MEDIUM', from: 30, to: 55, label: 'MED' },
    { band: 'HIGH', from: 55, to: 80, label: 'HIGH' },
    { band: 'CRITICAL', from: 80, to: 100, label: 'CRIT' },
];

function fmtClock(iso?: string) {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleTimeString();
}

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
    // Sidebar collapse is a per-viewer UI preference (wide screens only); storage may be unavailable.
    const [collapsed, setCollapsed] = useState<boolean>(() => {
        try { return localStorage.getItem('ds.sidebarCollapsed') === '1'; } catch { return false; }
    });
    const toggleCollapsed = () => setCollapsed((c) => {
        try { localStorage.setItem('ds.sidebarCollapsed', c ? '0' : '1'); } catch { /* ignore */ }
        return !c;
    });

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
    const explanation = selected ? explainCommand(selected.command) : null;
    const activeCount = sessions.filter((s) => s.status === 'active').length;
    const current = sessions.find((s) => s.sessionId === sessionId);
    const dead = isClosed || notFound;

    const toggleSelect = (id: string) => setSelectedId((cur) => (cur === id ? null : id));

    return (
        <div className="min-h-screen w-full bg-ds-bg text-ds-ink">
            <TopNav />

            <div className={`grid grid-cols-1 xl:h-[calc(100vh-54px)] xl:overflow-hidden ${collapsed ? 'xl:grid-cols-[52px_minmax(0,1fr)_320px]' : 'xl:grid-cols-[272px_minmax(0,1fr)_320px]'}`}>

                {/* ───────── LEFT: sessions ───────── */}
                {/* collapsed rail (wide screens only): one square per session */}
                {collapsed && (
                    <aside className="hidden flex-col items-center border-r-2 border-ds-line xl:flex xl:min-h-0">
                        <button
                            onClick={toggleCollapsed}
                            title="Expand session list"
                            className="mt-4 flex h-8 w-8 cursor-pointer items-center justify-center border border-ds-line font-mono text-[13px] text-ds-dim hover:border-ds-acc hover:text-ds-acc"
                        >
                            »
                        </button>
                        <div className="mt-3 font-mono text-[10px] text-ds-faint" title={`${activeCount} active`}>
                            <span className="font-bold text-ds-acc">{activeCount}</span>
                        </div>
                        <div className="ds-scroll mt-3 flex w-full flex-1 flex-col items-center gap-2 overflow-y-auto pb-4">
                            {sessions.map((s) => {
                                const on = s.sessionId === sessionId;
                                const live = s.status === 'active';
                                return (
                                    <button
                                        key={s.sessionId}
                                        title={`${s.sessionId} · ${live ? 'active' : 'closed'} · avg ${s.threatScore}`}
                                        onClick={() => navigate(`/dashboard/${encodeURIComponent(s.sessionId)}`)}
                                        className={`flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center border ${on ? 'border-ds-acc' : 'border-transparent hover:border-ds-line'}`}
                                    >
                                        <span className={`h-2.5 w-2.5 ${live ? 'bg-ds-acc' : 'bg-ds-ghost'}`} />
                                    </button>
                                );
                            })}
                        </div>
                    </aside>
                )}

                <aside className={`flex-col border-b-2 border-ds-line xl:min-h-0 xl:border-b-0 xl:border-r-2 ${collapsed ? 'flex xl:hidden' : 'flex'}`}>
                    <div className="flex items-center justify-between gap-2 px-5 pb-3 pt-5">
                        <button onClick={() => navigate('/sessions')} className="ds-label cursor-pointer hover:text-ds-ink">
                            ← All sessions
                        </button>
                        <div className="flex items-center gap-3">
                            <span className="font-mono text-[11px] text-ds-faint">
                                <span className="font-bold text-ds-acc">{activeCount}</span> active
                            </span>
                            <button
                                onClick={toggleCollapsed}
                                title="Collapse session list"
                                className="hidden h-6 w-6 cursor-pointer items-center justify-center border border-ds-line font-mono text-[12px] text-ds-dim hover:border-ds-acc hover:text-ds-acc xl:flex"
                            >
                                «
                            </button>
                        </div>
                    </div>
                    <div className="ds-scroll max-h-[260px] overflow-y-auto border-t border-ds-line xl:max-h-none xl:flex-1">
                        {sessions.length === 0 && (
                            <div className="px-5 py-6 font-mono text-[11.5px] text-ds-faint">No current sessions</div>
                        )}
                        {sessions.map((s) => {
                            const on = s.sessionId === sessionId;
                            const live = s.status === 'active';
                            const sb = bandOf(s.threatScore);
                            return (
                                <button
                                    key={s.sessionId}
                                    onClick={() => navigate(`/dashboard/${encodeURIComponent(s.sessionId)}`)}
                                    className={`block w-full cursor-pointer border-b border-l-2 border-b-ds-hair py-4 pl-[18px] pr-5 text-left transition-colors ${on ? 'border-l-ds-acc bg-ds-sel' : 'border-l-transparent hover:bg-ds-sel/70'}`}
                                >
                                    <div className="flex items-center justify-between">
                                        <span className={`font-mono text-[13px] font-bold ${on ? 'text-ds-ink' : live ? 'text-ds-soft' : 'text-ds-dim'}`}>{s.sessionId}</span>
                                        <span className={`h-2 w-2 ${live ? 'bg-ds-acc' : 'bg-ds-ghost'}`} title={live ? 'Active' : 'Closed'} />
                                    </div>
                                    <div className="mt-1 font-mono text-[11px] text-ds-faint">
                                        {s.ip} · {s.commandCount} cmd · avg <span className={BAND_STYLE[sb].text}>{s.threatScore}</span>
                                    </div>
                                </button>
                            );
                        })}
                    </div>
                </aside>

                {/* ───────── CENTER: adversary, feed, response ───────── */}
                <section className="flex flex-col border-b-2 border-ds-line xl:min-h-0 xl:border-b-0 xl:border-r-2">
                    {/* adversary identity */}
                    <div className="border-b-2 border-ds-line bg-ds-panel px-6 pb-5 pt-5">
                        <div className="flex items-start justify-between gap-6">
                            <div className="min-w-0">
                                <div className="ds-label mb-2">
                                    {sessionId ? <>Attacker · <span className="text-ds-ink">{sessionId}</span></> : 'All sessions (unfiltered view)'}
                                </div>
                                <div
                                    title={waiting ? undefined : profile.geo}
                                    className={`ds-display truncate text-[30px] leading-[1.05] ${waiting ? 'text-ds-ghost' : isClosed ? 'text-ds-dim' : 'text-ds-crit'}`}
                                >
                                    {waiting ? 'Awaiting attacker' : profile.geo}
                                </div>
                            </div>
                            {sessionId && (
                                <div className={`flex shrink-0 items-center gap-2 border px-3 py-1.5 ${dead ? 'border-ds-ghost' : 'border-ds-acc'}`}>
                                    <span className={`h-2 w-2 ${dead ? 'bg-ds-faint' : 'animate-[ds-pulse_1.6s_steps(1)_infinite] bg-ds-acc'}`} />
                                    <span className={`font-mono text-[11px] font-bold tracking-[0.14em] ${dead ? 'text-ds-dim' : 'text-ds-acc'}`}>
                                        {notFound ? 'NOT FOUND' : isClosed ? 'SESSION CLOSED' : 'LIVE'}
                                    </span>
                                </div>
                            )}
                        </div>
                        <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 md:grid-cols-4">
                            {[
                                { k: 'IP address', v: profile.ip },
                                { k: 'ISP', v: profile.isp },
                                { k: 'Organisation', v: profile.org || '—' },
                                { k: 'Connection', v: profile.type },
                            ].map((c) => (
                                <div key={c.k} className="min-w-0">
                                    <div className="mb-1 font-mono text-[10px] font-bold uppercase tracking-[0.14em] text-ds-faint">{c.k}</div>
                                    <div title={c.v} className={`truncate font-mono text-[13px] ${waiting ? 'text-ds-faint' : 'text-ds-ink'}`}>{c.v}</div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {sessionId && notFound && (
                        <div className="border-b border-ds-line bg-ds-high/10 px-6 py-2.5 font-mono text-[12px] text-ds-high">
                            Session {sessionId} not found. It may have ended before a backend restart.
                        </div>
                    )}

                    {/* feed */}
                    <div className="flex max-h-[520px] min-h-[260px] flex-col xl:max-h-none xl:min-h-0 xl:flex-1">
                        <LiveFeed logs={sessionLogs} selectedId={following ? null : selectedId} onSelect={toggleSelect} />
                    </div>

                    {/* selected command: what the attacker saw + what it does */}
                    <div className="flex shrink-0 flex-col border-t-2 border-ds-line bg-ds-panel md:h-[236px]">
                        <div className="flex items-baseline justify-between gap-4 px-6 pb-1 pt-4">
                            <span className="min-w-0 truncate font-mono text-[13px]">
                                {selected
                                    ? <><span className="text-ds-faint">ubuntu@prod-db-01:~$ </span><span className="font-bold text-ds-ink">{selected.command}</span></>
                                    : <span className="text-ds-faint">No command selected</span>}
                            </span>
                            <span className="shrink-0 font-mono text-[11px] text-ds-faint">
                                {!selected ? '' : following ? 'Latest · click a row to pick another' : 'Selected · click again for latest'}
                            </span>
                        </div>
                        <div className="grid min-h-0 flex-1 grid-cols-1 md:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
                            {/* left: AI output */}
                            <div className="ds-scroll min-h-0 overflow-y-auto px-6 pb-5 pt-3 font-mono">
                                <div className="ds-label mb-2">What the attacker saw</div>
                                {!selected ? (
                                    <div className="text-[12.5px] text-ds-faint">The AI's reply to each command will show here.</div>
                                ) : (
                                    <div className="whitespace-pre-wrap text-[12.5px] leading-relaxed text-ds-soft">
                                        {selected.response === undefined
                                            ? <span className="text-ds-faint">Output not captured: this command ran before the dashboard was opened.</span>
                                            : selected.response === '[silent execution]' || selected.response === ''
                                                ? <span className="text-ds-faint">No output. The honeypot ran this command silently (e.g. cd, touch, mkdir, rm).</span>
                                                : selected.response}
                                    </div>
                                )}
                            </div>
                            {/* right: built-in command reference */}
                            <div className="ds-scroll min-h-0 overflow-y-auto border-t border-ds-line px-6 pb-5 pt-3 md:border-l md:border-t-0">
                                <div className="ds-label mb-2">What this command does</div>
                                {!selected ? (
                                    <div className="font-mono text-[12.5px] text-ds-faint">Select a command to see an explanation.</div>
                                ) : !explanation ? (
                                    <div className="font-mono text-[12.5px] text-ds-faint">No explanation for this command in the built-in reference.</div>
                                ) : (
                                    <>
                                        <div className="text-[15px] font-bold text-ds-ink">{explanation.label}</div>
                                        <p className="mt-1.5 text-[13px] leading-relaxed text-ds-soft">{explanation.what}</p>
                                        <p className="mt-1.5 text-[13px] leading-relaxed text-ds-dim">
                                            <span className="text-ds-faint">Why attackers do it: </span>{explanation.why}
                                        </p>
                                        {explanation.mitre && (
                                            <div className="mt-3 inline-flex max-w-full items-center gap-2 border border-ds-line px-2 py-1 font-mono text-[10.5px]">
                                                <span className="font-bold tracking-[0.08em] text-ds-acc">MITRE {explanation.mitre.id}</span>
                                                <span className="truncate text-ds-dim">{explanation.mitre.name}</span>
                                            </div>
                                        )}
                                    </>
                                )}
                            </div>
                        </div>
                    </div>
                </section>

                {/* ───────── RIGHT: threat level, facts, export ───────── */}
                <aside className="flex flex-col px-6 py-5 xl:min-h-0">
                    <div className="ds-label">Threat level</div>

                    <div className={`ds-display mt-4 text-[96px] leading-[0.82] tracking-[-0.04em] ${!hasData ? 'text-ds-ghost' : band === 'LOW' ? 'text-ds-ink' : bandSt.text}`}>
                        {hasData ? threatScore : '–'}
                    </div>
                    <div className={`mt-3 self-start border-2 px-2.5 py-1 font-mono text-[12px] font-bold tracking-[0.14em] ${hasData ? bandSt.chip : 'border-ds-ghost text-ds-faint'}`}>
                        {hasData ? band : 'NO DATA'}
                    </div>

                    {/* 0-100 scale with marker */}
                    <div className="mt-6">
                        <div className="relative flex h-2 gap-0.5">
                            {SCALE.map((seg) => (
                                <div
                                    key={seg.band}
                                    className={`${hasData && seg.band === band ? BAND_STYLE[seg.band].traceBg : BAND_STYLE[seg.band].bandBg}`}
                                    style={{ width: `${seg.to - seg.from}%` }}
                                />
                            ))}
                            {hasData && (
                                <div
                                    className="absolute -top-1.5 h-5 w-[3px] bg-ds-ink"
                                    style={{ left: `calc(${Math.min(100, Math.max(0, threatScore))}% - 1.5px)` }}
                                />
                            )}
                        </div>
                        <div className="mt-2 flex font-mono text-[9.5px] tracking-[0.1em] text-ds-faint">
                            {SCALE.map((seg) => (
                                <span key={seg.band} style={{ width: `${seg.to - seg.from}%` }}>{seg.label}</span>
                            ))}
                        </div>
                    </div>
                    <p className="mt-4 text-[13px] leading-relaxed text-ds-dim">
                        Average score across {sessionLogs.length} {sessionLogs.length === 1 ? 'command' : 'commands'}.
                    </p>

                    {/* session facts */}
                    {sessionId && (
                        <dl className="mt-6 border-t border-ds-line pt-5 font-mono text-[12px]">
                            {[
                                { k: 'Source', v: current?.source === 'WEB' ? 'Browser simulator' : current?.source === 'SSH' ? 'SSH (port 2222)' : (current?.source ?? '—') },
                                { k: 'Started', v: fmtClock(current?.startTime) },
                                { k: 'Ended', v: isClosed ? fmtClock(current?.endTime ?? undefined) : '—' },
                            ].map((f) => (
                                <div key={f.k} className="flex justify-between gap-4 py-1.5">
                                    <dt className="text-ds-faint">{f.k}</dt>
                                    <dd className="m-0 truncate text-right text-ds-soft">{f.v}</dd>
                                </div>
                            ))}
                        </dl>
                    )}

                    <div className="hidden flex-1 xl:block" />

                    <div className="mt-6">
                        <ReportButton logs={sessionLogs} profile={profile} />
                    </div>
                </aside>
            </div>
        </div>
    );
}
