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

        // 1. Initialize Terminal
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

        // 2. Connect to Python FastAPI Backend
        socket.connect();

        const prompt = '\r\nubuntu@prod-db-01:~$ ';
        let commandBuffer = '';
        let isProcessing = false;

        // Boot Sequence
        term.writeln('\x1b[1;32mInitializing connection to target...\x1b[0m');
        setTimeout(() => {
            term.writeln('\x1b[1;32mConnection established.\x1b[0m');
            term.write(prompt);
        }, 800);

        // 3. Handle User Input (The Buffer)
        term.onData((data) => {
            if (isProcessing) return; // Lock terminal while waiting for Llama 3

            const char = data;

            if (char === '\r') {
                // ENTER KEY PRESSED
                if (commandBuffer.trim() === '') {
                    term.write(prompt);
                    return;
                }

                term.write('\r\n');
                isProcessing = true;

                // Emit to Python backend
                socket.emit('execute_command', { command: commandBuffer });

                // --- HACKATHON FALLBACK ---
                // If your backend isn't running yet, simulate a response locally
                if (!socket.connected) {
                    setTimeout(() => {
                        const cmd = commandBuffer.trim().toLowerCase();
                        let fakeOutput = `bash: ${cmd}: command not found`;

                        if (cmd === 'whoami') fakeOutput = 'root';
                        if (cmd === 'ls -la' || cmd === 'ls') fakeOutput = 'drwxr-xr-x 4 root root 4096 Apr 22 12:00 .\r\ndrwxr-xr-x 1 root root 4096 Apr 22 12:00 ..\r\n-rw-r--r-- 1 root root 312 Apr 22 12:00 .bashrc\r\n-rw-r--r-- 1 root root 1024 Apr 22 12:01 secure_keys.pem';
                        if (cmd.startsWith('cat /etc/passwd')) fakeOutput = 'root:x:0:0:root:/root:/bin/bash\r\nsshd:x:100:65534::/run/sshd:/usr/sbin/nologin\r\nubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash';
                        if (cmd === 'clear') {
                            term.clear();
                            term.write(prompt);
                            commandBuffer = '';
                            isProcessing = false;
                            return;
                        }

                        // Write the fake output
                        const lines = fakeOutput.split('\n');
                        lines.forEach((line) => term.writeln(line.replace('\r', '')));

                        term.write(prompt);
                        commandBuffer = '';
                        isProcessing = false;
                    }, 600);
                } else {
                    // Clear buffer if connected to real backend
                    commandBuffer = '';
                }
                // ---------------------------

            } else if (char === '\x7F') {
                // BACKSPACE KEY PRESSED
                if (commandBuffer.length > 0) {
                    commandBuffer = commandBuffer.slice(0, -1);
                    term.write('\b \b'); // Move back, write space, move back again
                }
            } else {
                // REGULAR TYPING
                commandBuffer += char;
                term.write(char);
            }
        });

        // 4. Listen for Real Llama 3 Responses
        socket.on('terminal_response', (data) => {
            // Split the string by newline so xterm formats it correctly
            const lines = data.output.split('\n');
            lines.forEach((line: string) => term.writeln(line.replace('\r', '')));

            term.write(prompt);
            isProcessing = false;
        });

        // Resize listener
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