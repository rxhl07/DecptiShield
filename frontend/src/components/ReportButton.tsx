import { useState } from 'react';
import { FileCode2, Download } from 'lucide-react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface ReportProps {
    logs: any[];
    profile: { ip: string, geo: string, type: string };
}

export default function ReportButton({ logs, profile }: ReportProps) {
    const [phase, setPhase] = useState<'idle' | 'loading' | 'done'>('idle');

    const generatePDF = () => {
        setPhase('loading');

        setTimeout(() => {
            const doc = new jsPDF();

            // Header
            doc.setFontSize(22);
            doc.setTextColor(220, 38, 38); // Red
            doc.text("DeceptiShield Forensics Report", 14, 20);

            doc.setFontSize(10);
            doc.setTextColor(100);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);
            // Log ids are "<sessionId>-<n>" and session ids contain a dash themselves (e.g. SSH-abc123),
            // so take everything before the LAST dash.
            const firstId: string = logs.length > 0 ? String(logs[0].id) : '';
            const sessionLabel = firstId.includes('-') ? firstId.slice(0, firstId.lastIndexOf('-')) : (firstId || 'N/A');
            doc.text(`Session ID: ${sessionLabel}`, 14, 34);

            // Threat Profile Section
            doc.setFontSize(14);
            doc.setTextColor(0);
            doc.text("Attacker Profile", 14, 45);

            autoTable(doc, {
                startY: 50,
                head: [['Attribute', 'Data']],
                body: [
                    ['IP Address', profile.ip],
                    ['Geo-Location', profile.geo],
                    ['Threat Actor Type', profile.type],
                    ['Total Commands Executed', logs.length.toString()],
                    ['Final Session Threat Avg', logs.length > 0 ? logs[logs.length - 1].score + "%" : "0%"],
                ],
                theme: 'grid',
                headStyles: { fillColor: [220, 38, 38] }
            });

            // Command Log Section
            const finalY = (doc as any).lastAutoTable.finalY || 50;
            doc.setFontSize(14);
            doc.text("Command Execution Log", 14, finalY + 15);

            const tableData = logs.map(log => [
                log.timestamp.slice(11),
                log.command,
                log.risk,
                log.score.toString()
            ]);

            autoTable(doc, {
                startY: finalY + 20,
                head: [['Time', 'Command', 'Risk Level', 'Threat Score']],
                body: tableData,
                theme: 'striped',
                headStyles: { fillColor: [30, 41, 59] },
                didParseCell: function (data) {
                    // Color code the Risk Level column
                    if (data.section === 'body' && data.column.index === 2) {
                        if (data.cell.raw === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
                        if (data.cell.raw === 'HIGH') data.cell.styles.textColor = [249, 115, 22];
                    }
                }
            });

            // Save the file
            doc.save(`DeceptiShield_Report_${profile.ip}.pdf`);
            setPhase('done');

            // Reset button after 3 seconds
            setTimeout(() => setPhase('idle'), 3000);
        }, 1500);
    };

    const disabled = phase !== 'idle' || logs.length === 0;
    const tone =
        phase === 'done' ? 'border-ds-acc text-ds-acc'
            : phase === 'loading' ? 'border-ds-line text-ds-dim'
                : logs.length === 0 ? 'border-ds-line text-ds-faint'
                    : 'border-ds-ink text-ds-ink hover:border-ds-acc hover:text-ds-acc';

    return (
        <div className="flex flex-col">
            <button
                disabled={disabled}
                onClick={generatePDF}
                className={`flex w-full items-center justify-between gap-3 border-2 bg-ds-bg px-4 py-3.5 text-left transition-colors enabled:cursor-pointer ${tone}`}
            >
                <span className="flex items-center gap-2.5 text-[15px] font-bold uppercase tracking-[0.02em]">
                    {phase === 'done' ? <Download size={16} /> : <FileCode2 size={16} />}
                    {phase === 'loading' ? 'Building report…' : phase === 'done' ? 'PDF downloaded' : 'Export forensic PDF'}
                </span>
                <span className="font-mono text-[11px] tracking-[0.08em] text-ds-dim">
                    {logs.length} CMD
                </span>
            </button>
            {logs.length === 0 && (
                <p className="mt-2 font-mono text-[11px] text-ds-faint">Available once the session has commands.</p>
            )}
        </div>
    );
}