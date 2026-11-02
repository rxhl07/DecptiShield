import { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { socket } from '../socket';
import TopNav from './TopNav';

export default function AttackerTerminal() {
    const terminalRef = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();

    useEffect(() => {
        if (!terminalRef.current) return;
        terminalRef.current.innerHTML = '';

        const term = new Terminal({
            // Cyber theme colours (visual only). ANSI red/blue/green are used by the prompts.
            theme: {
                background: '#0A0B0C',
                foreground: '#C8C8C0',
                cursor: '#C8C8C0',
                cursorAccent: '#0A0B0C',
                selectionBackground: '#B8FF0055',
                red: '#FF5F57',
                brightRed: '#FF6E66',
                green: '#6FBF5A',
                brightGreen: '#7FD16A',
                blue: '#4A9BE0',
                brightBlue: '#5AABF0',
            },
            // System monospace fonts (no web-font loading race when xterm measures character width)
            fontFamily: '"Cascadia Mono", Consolas, "Courier New", monospace',
            fontSize: 15,
            lineHeight: 1.25,
            cursorBlink: true,
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        term.open(terminalRef.current);
        fitAddon.fit();
        // Only reconnect if fully shut down; calling connect() while the socket is still
        // connecting sends a duplicate CONNECT that the server rejects (socket gets dropped).
        if (!socket.active) socket.connect();

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
        <div className="flex h-screen w-full flex-col bg-ds-bg text-ds-ink">
            <TopNav />

            <div className="flex min-h-0 flex-1 flex-col items-center bg-ds-panel px-4 pb-4 pt-6 sm:px-7">
                {/* page header */}
                <div className="mb-4 flex w-full max-w-[1120px] flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <p className="ds-label mb-1.5">Attack simulator</p>
                        <h1 className="m-0 text-[20px] font-bold uppercase tracking-[-0.01em]">What the intruder sees</h1>
                        <p className="mt-1.5 font-mono text-[12px] text-ds-dim">
                            Type <span className="text-ds-acc">ssh admin@192.168.1.100</span>, any password, then try commands like
                            <span className="text-ds-ink"> whoami</span> or <span className="text-ds-ink">cat /etc/passwd</span>.
                        </p>
                    </div>
                    <button
                        onClick={() => navigate('/sessions')}
                        className="flex shrink-0 cursor-pointer items-center gap-2 self-start border-2 border-ds-line px-3 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.14em] text-ds-dim transition-colors hover:border-ds-acc hover:text-ds-acc sm:self-auto"
                    >
                        <ArrowLeft size={14} /> Return to SOC
                    </button>
                </div>

                {/* terminal window */}
                <div className="flex min-h-0 w-full max-w-[1120px] flex-1 flex-col overflow-hidden rounded-[10px] border border-[#2A2B2D] bg-[#0A0B0C] shadow-[0_22px_60px_-18px_rgba(0,0,0,.6),0_2px_6px_rgba(0,0,0,.35)]">
                    <div className="grid h-[38px] shrink-0 grid-cols-[1fr_auto_1fr] items-center border-b border-[#2A2B2D] bg-[#1A1B1D] px-3">
                        <div className="flex items-center gap-2">
                            <span className="h-3 w-3 rounded-full bg-[#FF5F57]" />
                            <span className="h-3 w-3 rounded-full bg-[#FEBC2E]" />
                            <span className="h-3 w-3 rounded-full bg-[#28C840]" />
                        </div>
                        <div className="truncate text-center font-mono text-[11.5px] font-semibold text-[#8A8A82]">root@kali: ~ — bash</div>
                        <div />
                    </div>
                    <div className="min-h-0 flex-1 px-4 py-3">
                        <div className="h-full w-full" ref={terminalRef} />
                    </div>
                </div>

                <p className="mt-3 w-full max-w-[1120px] font-mono text-[10.5px] tracking-[0.04em] text-ds-faint">
                    Every reply after login is generated by Llama 3 on the host. No file, user or password hash shown here is real.
                </p>
            </div>
        </div>
    );
}