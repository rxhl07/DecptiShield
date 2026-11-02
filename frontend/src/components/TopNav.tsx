import { Link, useLocation } from 'react-router-dom';

// Shared top bar: brand + page tabs. Navigation only (existing routes), no data.
const TABS = [
    { label: 'Overview', to: '/', match: (p: string) => p === '/' },
    { label: 'Attacker terminal', to: '/attacker', match: (p: string) => p.startsWith('/attacker') },
    { label: 'Dashboard', to: '/sessions', match: (p: string) => p.startsWith('/sessions') || p.startsWith('/dashboard'), accent: true },
];

export default function TopNav() {
    const { pathname } = useLocation();

    return (
        <nav className="sticky top-0 z-40 flex h-[54px] items-stretch border-b-2 border-ds-line bg-ds-bg">
            <Link to="/" className="flex shrink-0 items-center gap-2.5 border-r-2 border-ds-line px-[18px]">
                <span className="h-[13px] w-[13px] bg-ds-acc" />
                <span className="text-[15px] font-extrabold uppercase tracking-[0.06em] text-ds-ink [font-stretch:112%]">DeceptiShield</span>
            </Link>
            <div className="flex min-w-0 items-stretch overflow-x-auto">
                {TABS.map((t) => {
                    const active = t.match(pathname);
                    const activeCls = t.accent ? 'bg-ds-acc text-ds-bg' : 'bg-ds-ink text-ds-bg';
                    return (
                        <Link
                            key={t.to}
                            to={t.to}
                            className={`flex items-center whitespace-nowrap border-r-2 border-ds-line px-5 font-mono text-[11px] font-bold uppercase tracking-[0.16em] transition-colors ${active ? activeCls : 'text-ds-dim hover:text-ds-ink'}`}
                        >
                            {t.label}
                        </Link>
                    );
                })}
            </div>
            <div className="flex-1" />
        </nav>
    );
}
