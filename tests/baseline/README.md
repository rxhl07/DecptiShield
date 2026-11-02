# Baseline test set

Fixed commands for judging DeceptiShield on response time, consistency and accuracy. Use the same commands for every version, so each change can be compared fairly.

## Running it

On the laptop running the project:

```
cd backend
uvicorn main:socket_app --host 0.0.0.0 --port 8000
```

Restart the backend before each run. Check `ollama ps` shows the model on the GPU.

On the testing laptop:

```
cd tests/baseline
python run_baseline.py --target ssh --host <project-laptop-ip> --label baseline
python run_baseline.py --target web --host <project-laptop-ip> --label baseline-web
python compare.py baseline tuned
```

The second laptop only needs `paramiko` and `python-socketio[client]`. Over ngrok, use `--host` and `--ssh-port` from `ngrok tcp 2222`, and `--web-url` from `ngrok http 8000`.

Results are saved in `results/<label>.json`, including the real output of every failed check.

## What the scores mean

- **accuracy**: gives the answer a real machine would.
- **consistency**: agrees with itself across repeats, related commands and new sessions.
- **character**: never sounds like an AI, even under prompt injection.
- **predictable commands** in the timings have fixed answers. **Invented output** needs made-up content, such as a log file.

## Other files

- `capture_reference.py` stores real Ubuntu answers in `commands.json` using WSL. Only rerun it after adding a `"ref"` check.
- `python run_baseline.py --target wsl --label selftest` runs the file tests on real bash. Every check should pass; a failure there means the test is wrong.
