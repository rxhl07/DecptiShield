import { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { socket } from '../socket';

export default function AttackerTerminal() {
    const terminalRef = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();

    useEffect(() => {
        if (!terminalRef.current) return;
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
            // Ignore escape sequences (arrow keys, Home/End, Delete, F-keys): this shell has
            // no history/cursor movement, and the raw codes would otherwise be sent as a command.
            if (data.startsWith('\x1b')) return;

            for (const char of data) {
                if (char === '\r' || char === '\n') {
                    term.write('\r\n');
                    const cmd = commandBuffer.trim();
                    commandBuffer = '';

                    if (state === 'LOCAL') {
                        if (cmd.toLowerCase().includes('ssh')) {
                            term.write("admin@192.168.1.100's password: ");
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
                            term.write(remotePrompt);
                            state = 'REMOTE';
                            isProcessing = false;
                        }, 600);
                        continue;
                    }

                    if (state === 'REMOTE') {
                        if (cmd === '') {
                            term.write(remotePrompt);
                        } else if (cmd === 'exit' || cmd === 'logout') {
                            term.writeln('Connection to 192.168.1.100 closed.');
                            state = 'LOCAL';
                            term.write(localPrompt);
                        } else {
                            isProcessing = true;
                            socket.emit('execute_command', { command: cmd });
                        }
                    }
                } else if (char === '\x7F' || char === '\b') {
                    if (commandBuffer.length > 0) {
                        commandBuffer = commandBuffer.slice(0, -1);
                        if (state !== 'PASSWORD') term.write('\b \b');
                    }
                } else if (char < ' ') {
                    // Other control characters (Tab, Ctrl+key): ignore instead of adding to the command
                    continue;
                } else {
                    commandBuffer += char;
                    if (state !== 'PASSWORD') term.write(char);
                }
            }
        });

        // Appends streaming tokens chunk-by-chunk
        socket.on('terminal_chunk', (data: { chunk: string }) => {
            term.write(data.chunk.replace(/\n/g, '\r\n'));
        });

        // Re-renders the shell prompt once the LLM finishes generation
        socket.on('terminal_end', () => {
            term.write(remotePrompt);
            isProcessing = false;
        });

        return () => {
            socket.off('terminal_chunk');
            socket.off('terminal_end');
            socket.disconnect();
            term.dispose();
        };
    }, []);

    return (
        <div className="h-screen w-full bg-[#050505] flex flex-col relative">
            <div className="h-14 bg-white/5 border-b border-white/10 flex items-center justify-between px-8">
                <span className="text-[#10B981] font-mono font-bold uppercase">SSH Session // Active</span>
                <button onClick={() => navigate('/sessions')} className="flex items-center gap-2 text-slate-500 hover:text-white font-mono text-xs tracking-widest transition-colors">
                    <ArrowLeft size={14} /> Return to SOC
                </button>
            </div>
            <div className="flex-grow p-6" ref={terminalRef} />
        </div>
    );
}