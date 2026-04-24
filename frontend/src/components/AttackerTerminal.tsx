import { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { socket } from '../socket';

const FAKE_PROFILES = [
    { ip: "185.220.101.47", type: "TOR EXIT NODE" }, // Real German Tor Node
    { ip: "194.126.177.81", type: "BULLETPROOF HOSTING" }, // Real Russian IP
    { ip: "45.133.192.12", type: "STATE SPONSORED THREAT" },
    { ip: "103.22.16.90", type: "KNOWN BOTNET C2" } // Real Chinese IP
];

export default function AttackerTerminal() {
    const terminalRef = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();

    useEffect(() => {
        if (!terminalRef.current) return;

        // --- ANTI-GHOST TERMINAL FIX ---
        // Clears the DOM to prevent React Strict Mode from attaching two listeners
        terminalRef.current.innerHTML = '';

        const term = new Terminal({
            theme: { background: '#050505', foreground: '#10B981', cursor: '#10B981' },
            fontFamily: '"Fira Code", monospace',
            fontSize: 16,
            cursorBlink: true,
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        term.open(terminalRef.current);
        fitAddon.fit();
        socket.connect();

        let state: 'LOCAL' | 'PASSWORD' | 'REMOTE' = 'LOCAL';
        const localPrompt = '\r\n\x1b[1;31mroot@kali\x1b[0m:\x1b[1;34m~\x1b[0m$ ';
        const remotePrompt = '\r\nubuntu@prod-db-01:~$ ';

        let commandBuffer = '';
        let isProcessing = false;

        term.write(localPrompt);

        // COPY HANDLER ONLY
        term.attachCustomKeyEventHandler((e) => {
            if (e.ctrlKey && e.code === 'KeyC' && e.type === 'keydown') {
                const selection = term.getSelection();
                if (selection) {
                    navigator.clipboard.writeText(selection);
                    return false;
                }
            }
            return true;
        });

        term.onData((data) => {
            if (isProcessing) return;

            // --- THE BULLETPROOF INPUT PROCESSOR ---
            // Processes text character-by-character to perfectly handle large pasted strings
            for (let i = 0; i < data.length; i++) {
                const char = data[i];

                if (char === '\r' || char === '\n') { // ENTER KEY OR PASTED NEWLINE
                    term.write('\r\n');
                    const cmd = commandBuffer.trim();
                    commandBuffer = '';

                    if (state === 'LOCAL') {
                        if (cmd.includes('ssh')) {
                            term.write('admin@192.168.1.100\'s password: ');
                            state = 'PASSWORD';
                        } else if (cmd === '') {
                            term.write(localPrompt);
                        } else {
                            term.writeln(`bash: ${cmd}: command not found`);
                            term.write(localPrompt);
                        }
                        continue;
                    }

                    if (state === 'PASSWORD') {
                        isProcessing = true;
                        setTimeout(() => {
                            term.writeln('\x1b[1;32mWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-76-generic x86_64)\x1b[0m');
                            term.writeln(' * Documentation:  https://help.ubuntu.com');
                            term.writeln(' * Management:     https://landscape.canonical.com');
                            term.writeln(' * Support:        https://ubuntu.com/advantage');
                            term.write(remotePrompt);

                            state = 'REMOTE';
                            isProcessing = false;

                            const randomProfile = FAKE_PROFILES[Math.floor(Math.random() * FAKE_PROFILES.length)];
                            socket.emit('session_start', randomProfile);
                        }, 800);
                        continue;
                    }

                    if (state === 'REMOTE') {
                        if (cmd === '') {
                            term.write(remotePrompt);
                            continue;
                        }
                        if (cmd === 'clear') {
                            term.clear();
                            term.write(remotePrompt);
                            continue;
                        }
                        if (cmd === 'exit' || cmd === 'logout') {
                            term.writeln('logout');
                            term.writeln('Connection to 192.168.1.100 closed.');
                            state = 'LOCAL';
                            term.write(localPrompt);
                            continue;
                        }

                        isProcessing = true;
                        socket.emit('execute_command', { command: cmd });
                    }

                } else if (char === '\x7F' || char === '\b') { // BACKSPACE
                    if (commandBuffer.length > 0) {
                        commandBuffer = commandBuffer.slice(0, -1);
                        if (state !== 'PASSWORD') term.write('\b \b');
                    }
                } else { // REGULAR TYPING OR PASTING
                    commandBuffer += char;
                    if (state !== 'PASSWORD') term.write(char);
                }
            }
        });

        socket.on('terminal_response', (data) => {
            const lines = data.output.split('\n');
            lines.forEach((line: string) => term.writeln(line.replace('\r', '')));
            term.write(remotePrompt);
            isProcessing = false;
        });

        const handleResize = () => fitAddon.fit();
        window.addEventListener('resize', handleResize);

        return () => {
            window.removeEventListener('resize', handleResize);
            socket.off('terminal_response');
            socket.disconnect();
            term.dispose();
        };
    }, []);

    return (
        <div className="h-screen w-full bg-[#050505] flex flex-col relative">
            <div className="h-14 bg-white/5 border-b border-white/10 flex items-center justify-between px-8">
                <span className="text-[#10B981] font-mono text-sm tracking-widest uppercase font-bold">SSH Session // Active</span>
                <button onClick={() => navigate('/dashboard')} className="flex items-center gap-2 text-slate-500 hover:text-white font-mono text-xs tracking-widest transition-colors">
                    <ArrowLeft size={14} /> Return to SOC
                </button>
            </div>
            <div className="flex-grow p-6" ref={terminalRef} />
        </div>
    );
}