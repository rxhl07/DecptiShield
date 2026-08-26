# DeceptiShield — Development Workflow Setup

## Context

The codebase reached a state where `main` was a stub while the real project lived on a
personal branch (`rahul`), the same repo got cloned twice nested inside itself, and
`requirements.txt` was missing two runtime dependencies (`paramiko`, `httpx`) so a clean
install could not start the project. None of that is a coding mistake — it's the absence of
a defined workflow.

This plan sets up reproducible environments and a branching model for a 4-person team, so
onboarding a machine is one command and nobody's work drifts onto a private branch again.

**Decisions made:**
- Docker Compose runs backend + honeypot + MongoDB. Frontend runs natively (fast Vite HMR).
  Ollama runs natively on the host (GPU access, 4.7GB model).
- MongoDB is a local container for dev; the Atlas URI stays available via `.env` for demos.
- Trunk-based branching, `main` protected.

Out of scope: the code bugs from the earlier review (socket disconnect, duplicate Socket.IO
handlers, divergent threat scorers). Those are tracked separately at the bottom.

---

## Part 1 — Configuration (do this first; everything else depends on it)

The blocker for containerizing is that service URLs are hardcoded to `localhost`, which is
wrong inside a container. Every service needs to read its endpoints from the environment.

**Create `.env.example`** at the repo root (commit this; `.env` stays gitignored):

```
# Mongo — compose overrides this to mongodb://mongo:27017
MONGO_URI=mongodb://localhost:27017
DB_NAME=deceptishield

# Ollama on the host — compose overrides to http://host.docker.internal:11434
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Backend — compose overrides to http://backend:8000
BACKEND_URL=http://localhost:8000

HONEYPOT_PORT=2222
```

**Replace `backend/config.py`.** Current version uses `load_dotenv(dotenv_path="../.env")`,
which is CWD-relative and only resolves if you `cd backend` first. Make it `__file__`-relative
and add the missing values:

- Derive the `.env` path from `Path(__file__).resolve().parent.parent / ".env"`
- Export `MONGO_URI`, `DB_NAME`, `OLLAMA_URL`, `OLLAMA_MODEL`, `BACKEND_URL`, `HONEYPOT_PORT`
- Env vars already set (as Docker does) must win over the `.env` file — `load_dotenv` does
  this by default, so don't pass `override=True`

**Add `honeypot/config.py`** as a near-copy. Do *not* try to import across folders — the two
run as separate containers with separate build contexts, and a shared package is more
machinery than this earns.

**Replace the hardcoded URLs:**

| File | Currently | Change to |
|---|---|---|
| `honeypot/ollama_client.py:9` | `"http://localhost:11434/api/generate"` | `f"{config.OLLAMA_URL}/api/generate"` |
| `honeypot/socket_emitter.py` | `"http://localhost:8000/internal/emit"` | `f"{config.BACKEND_URL}/internal/emit"` |
| `honeypot/db_writer.py` | its own `load_dotenv("../.env")` block | `import config` |
| `backend/main.py` | inline `"http://localhost:11434/api/generate"` | `config.OLLAMA_URL` |
| `frontend/src/socket.ts` | `"http://localhost:8000"` | `import.meta.env.VITE_BACKEND_URL ?? "http://localhost:8000"` |

Also add `frontend/.env.example` with `VITE_BACKEND_URL=http://localhost:8000`. Vite only
exposes vars prefixed `VITE_`.

**Make the Mongo failure loud.** `db_writer.py` prints "Successfully connected" before
pymongo has connected to anything (the client is lazy), so a bad URI looks like success.
Add `self.client.admin.command("ping")` inside the `try` before the success print.

---

## Part 2 — Dependencies

**Rewrite `requirements.txt`** with the two missing packages and version pins:

```
fastapi==0.115.6
uvicorn[standard]==0.34.0
python-socketio==5.12.1
pymongo==4.10.1
python-dotenv==1.0.1
pydantic==2.10.4
paramiko==3.5.0      # missing — honeypot/ssh_server.py
httpx==0.28.1        # missing — 4 modules import it
```

Pin at whatever `pip index versions <pkg>` reports; the point is that all four machines
resolve identically, not these exact numbers.

Frontend already has `package-lock.json` — the rule is **`npm ci`, never `npm install`**,
for reproducible resolution.

---

## Part 3 — Docker Compose

**`backend/Dockerfile`** — `python:3.12-slim` base (matches the committed `.pyc` files),
copy `requirements.txt` and `pip install` *before* copying source so layer caching survives
code edits, then `uvicorn main:socket_app --host 0.0.0.0 --port 8000`. Binding `0.0.0.0`
rather than localhost is required for the port to be reachable from outside the container.

**`honeypot/Dockerfile`** — same base and layering, `CMD ["python", "ssh_server.py"]`.

**`docker-compose.yml`** at the repo root, three services:

- **`mongo`** — `mongo:7` image, named volume `mongo-data` at `/data/db` so the DB survives
  `docker compose down`. Expose `27017` to the host so you can inspect it with Compass.
- **`backend`** — builds `./backend`, port `8000:8000`, `env_file: .env`, plus overrides:
  `MONGO_URI=mongodb://mongo:27017`, `OLLAMA_URL=http://host.docker.internal:11434`.
  `depends_on: [mongo]`. Bind-mount `./backend:/app` so `--reload` picks up edits.
- **`honeypot`** — builds `./honeypot`, port `2222:2222`, same env plus
  `BACKEND_URL=http://backend:8000`. `depends_on: [backend]`. Mount a named volume
  `honeypot-keys` at the working directory so the generated `server.key` persists —
  otherwise the host key changes on every restart and SSH clients throw
  REMOTE HOST IDENTIFICATION HAS CHANGED warnings.

Add `extra_hosts: ["host.docker.internal:host-gateway"]` to `backend` and `honeypot`. It's a
no-op on Windows and Mac but is what makes Ollama reachable when a teammate runs Linux.

**Add `.dockerignore`** at the root: `__pycache__/`, `*.pyc`, `.env`, `node_modules/`,
`.git/`, `frontend/`.

---

## Part 4 — Git hygiene

**Stop tracking build artifacts.** `backend/__pycache__/*.pyc` is committed:

```
git rm -r --cached backend/__pycache__
```

**Extend `.gitignore`** (currently only `.env` and `node_modules/`):

```
__pycache__/
*.pyc
.env
.env.local
node_modules/
dist/
server.key
venv/
.venv/
```

`server.key` matters — it's the honeypot's SSH host private key, generated at runtime and
never something to commit.

**Branching — trunk-based:**

- `main` is the only long-lived branch. Protect it on GitHub: no direct pushes, require 1
  approving review, require the CI check to pass
- Branch names `feat/<thing>` or `fix/<thing>` — never a person's name
- Branch lives under 3 days; squash-merge; delete after merge
- `git pull --rebase` to keep history flat
- Ownership zones for review, not for branches: frontend / backend / honeypot / infra.
  Anyone edits anything; the zone owner reviews.

**Cleanup once `main` contains everything:** delete `rahul`, `pika`, and `dev` on the remote.
Their history is preserved in `main`.

**`.github/workflows/ci.yml`** — on PR to `main`, two jobs:
- backend: `pip install -r requirements.txt`, then `python -m compileall backend honeypot`
  (this alone would have caught the missing `paramiko`)
- frontend: `npm ci`, `npm run lint`, `npm run build` (the build runs `tsc -b`, so it
  typechecks too)

---

## Part 5 — README

Rewrite the current 4-line `readme.md` to cover: prerequisites (Docker Desktop, Node 20+,
Ollama), first-time setup, daily startup, and the port table.

```
# First time
cp .env.example .env
cp frontend/.env.example frontend/.env
ollama pull llama3
cd frontend && npm ci

# Every day
ollama serve                      # terminal 1 (host)
docker compose up                 # terminal 2 — backend, honeypot, mongo
cd frontend && npm run dev        # terminal 3
```

| Service | Port | Runs in |
|---|---|---|
| frontend | 5173 | host (npm) |
| backend | 8000 | container |
| honeypot | 2222 | container |
| mongo | 27017 | container |
| ollama | 11434 | host |

---

## Verification

1. `docker compose up --build` — all three services start; backend logs no Mongo error
   (the new `ping` proves the connection is real, not lazy).
2. `curl http://localhost:8000/` → `database_config: "Loaded"`.
3. `npm run dev`, open `/attacker`, fake-ssh in, run `touch foo.txt` then `ls` — `foo.txt`
   appears, confirming the `VirtualFileSystem` context still reaches Ollama through the
   container boundary via `host.docker.internal`.
4. `/dashboard` in a second tab shows the live feed updating.
5. `ssh admin@localhost -p 2222` — the real honeypot path. Run a command, confirm it reaches
   the dashboard (this proves `BACKEND_URL=http://backend:8000` container-to-container
   networking works).
6. `docker compose restart honeypot`, then SSH again — **no** host-key-changed warning,
   proving the `honeypot-keys` volume persists `server.key`.
7. `docker compose down && docker compose up` — previous sessions still in Mongo, proving
   the `mongo-data` volume.
8. Fresh-clone test on a teammate's machine: clone, copy both `.env` files, `npm ci`,
   `docker compose up`. This is the real proof the workflow works.

## Follow-up: code bugs (separate PRs)

From the earlier review, in priority order:

1. `socket.disconnect()` in `AttackerTerminal.tsx:152` with no `socket.connect()` in
   `Dashboard.tsx` — "Return to SOC" permanently kills the live feed
2. Duplicate `connect`/`disconnect` handlers; `emit_new_command()` is dead code
3. Two divergent threat scorers — consolidate on `honeypot/threat_scorer.py`
4. `ReportButton` prop type omits `isp`, so OSINT ISP never reaches the PDF
5. Decide whether the Sepolia/IPFS/reinforcement-learning claims in the UI get implemented
   or removed from the copy
