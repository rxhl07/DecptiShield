// Visual helpers for severity bands (Cyber theme). Thresholds match the backend:
// LOW < 30, MEDIUM 30-54, HIGH 55-79, CRITICAL 80+.
export type Band = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export function bandOf(score: number): Band {
    if (score >= 80) return 'CRITICAL';
    if (score >= 55) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
}

// Normalise a severity string from the backend; unknown values fall back to LOW.
export function asBand(sev: string | undefined): Band {
    return sev === 'MEDIUM' || sev === 'HIGH' || sev === 'CRITICAL' ? sev : 'LOW';
}

interface BandStyle {
    glyph: string;   // ▪ count = severity rank, readable without colour
    chip: string;    // filled chip classes
    outline: string; // quieter outlined chip classes (text + border only)
    text: string;    // coloured text
    mark: string;    // left-border colour
    bandBg: string;  // muted background for the band ladder
    traceBg: string; // bar colour in score trace
}

export const BAND_STYLE: Record<Band, BandStyle> = {
    LOW: {
        glyph: '▪',
        chip: 'bg-transparent text-ds-low border-ds-line',
        outline: 'text-ds-low border-ds-line',
        text: 'text-ds-low',
        mark: 'border-l-ds-low-mark',
        bandBg: 'bg-ds-low-band',
        traceBg: 'bg-ds-ghost',
    },
    MEDIUM: {
        glyph: '▪▪',
        chip: 'bg-ds-med text-ds-med-ink border-ds-med',
        outline: 'text-ds-med border-ds-med/60',
        text: 'text-ds-med',
        mark: 'border-l-ds-med',
        bandBg: 'bg-ds-med-band',
        traceBg: 'bg-ds-med',
    },
    HIGH: {
        glyph: '▪▪▪',
        chip: 'bg-ds-high text-ds-high-ink border-ds-high',
        outline: 'text-ds-high border-ds-high/60',
        text: 'text-ds-high',
        mark: 'border-l-ds-high',
        bandBg: 'bg-ds-high-band',
        traceBg: 'bg-ds-high',
    },
    CRITICAL: {
        glyph: '▪▪▪▪',
        chip: 'bg-ds-crit text-ds-crit-ink border-ds-crit',
        outline: 'text-ds-crit border-ds-crit/70',
        text: 'text-ds-crit',
        mark: 'border-l-ds-crit',
        bandBg: 'bg-ds-crit-band',
        traceBg: 'bg-ds-crit',
    },
};

export const BAND_RANGE: Record<Band, string> = {
    CRITICAL: '80–100',
    HIGH: '55–79',
    MEDIUM: '30–54',
    LOW: '0–29',
};
