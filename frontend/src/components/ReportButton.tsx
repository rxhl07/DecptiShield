import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
            doc.text(`Session ID: ${logs.length > 0 ? logs[0].id.split('-')[0] : 'N/A'}`, 14, 34);

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

    return (
        <div className="flex flex-col h-full relative justify-center">
            <button
                disabled={phase !== 'idle' || logs.length === 0}
                onClick={generatePDF}
                className="w-full px-6 py-5 rounded-xl font-black text-sm tracking-widest uppercase transition-all duration-300 flex items-center justify-center gap-3 disabled:opacity-50"
                style={{
                    background: phase === 'loading' ? 'rgba(239,68,68,0.1)' : phase === 'done' ? 'rgba(16,185,129,0.15)' : '#EF4444',
                    border: `1px solid ${phase === 'loading' ? 'rgba(239,68,68,0.3)' : phase === 'done' ? 'rgba(16,185,129,0.5)' : '#EF4444'}`,
                    color: phase === 'done' ? '#10B981' : phase === 'loading' ? '#EF4444' : '#fff',
                }}
            >
                {phase === 'loading' ? (
                    <span className="animate-pulse flex items-center gap-2"><FileCode2 size={18} /> COMPILING FORENSICS...</span>
                ) : phase === 'done' ? (
                    <span className="flex items-center gap-2"><Download size={18} /> PDF DOWNLOADED</span>
                ) : (
                    <span className="flex items-center gap-2"><FileCode2 size={18} /> GENERATE FORENSIC PDF</span>
                )}
            </button>
            {logs.length === 0 && <p className="text-center text-[10px] text-slate-500 mt-3 font-mono">Awaiting session data to generate report.</p>}
        </div>
    );
}