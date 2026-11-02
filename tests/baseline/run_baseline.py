"""
Baseline test set: response time, consistency and accuracy.

Connects from outside like a real attacker, so it needs no project code and runs
the same way against any version of the backend, on this laptop or another one.

    python run_baseline.py --target ssh --host 192.168.1.20 --label baseline
    python run_baseline.py --target web --host 192.168.1.20 --label baseline-web
    python run_baseline.py --target wsl --label selftest

--target wsl runs the "local_safe" groups on a real bash shell as a check of the
test set itself: anything that fails there is a bad test, not a honeypot problem.
"""
import argparse
import json
import re
import socket
import statistics
import subprocess
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
COMMAND_TIMEOUT = 90.0

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PROMPT = re.compile(r"(?:^|\n)([\w.-]+@[\w.-]+:[^\n]*[$#] )$")

# Things a real server never prints.
LEAK = re.compile(
    r"\b(as an ai|an ai\b|language model|i cannot|i can't|i'm sorry|assistant|"
    r"simulat\w*|honeypot|sandbox|system prompt|capture-the-flag|llama|ollama)\b",
    re.I,
)
PROSE = re.compile(
    r"^\s*(here is|here's|here are|sure[,!]|certainly|of course|note:|please note|"
    r"this (command|file|output)|the (output|command) )",
    re.I | re.M,
)
INVENTED_PROMPT = re.compile(r"^\s*[\w.-]+@[\w.-]+:\S*\s*[$#]", re.M)


def clean_text(text):
    return ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")


class Reply:
    def __init__(self, output, first, done, prompt="", timed_out=False):
        self.output = output.strip("\n")
        self.first = first
        self.done = done
        self.prompt = prompt
        self.timed_out = timed_out


class SSHSession:
    """An interactive shell, read the way a person would: until the prompt returns."""

    def __init__(self, host, port, username="ubuntu"):
        import paramiko

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port, username=username, password="password123",
                            look_for_keys=False, allow_agent=False, timeout=15)
        self.channel = self.client.invoke_shell(width=200, height=50)
        self._read_until_prompt(30.0)

    def _read_until_prompt(self, limit):
        """Returns (text, seconds to first data past the echo, seconds to prompt)."""
        start = time.perf_counter()
        buffer, first, done = "", None, None
        while time.perf_counter() - start < limit:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65536).decode("utf-8", "replace")
                if not chunk:
                    break
                buffer += chunk
                text = clean_text(buffer)
                if first is None and "\n" in text and text.split("\n", 1)[1]:
                    first = time.perf_counter() - start
                if PROMPT.search(text):
                    done = time.perf_counter() - start
                    # A model can print a prompt mid-reply, so make sure that was the end.
                    time.sleep(0.2)
                    if not self.channel.recv_ready():
                        return text, first, done
                    done = None
            elif self.channel.exit_status_ready() or self.channel.closed:
                break
            else:
                time.sleep(0.005)
        return clean_text(buffer), first, done

    def run(self, command):
        self.channel.send(command + "\n")
        text, first, done = self._read_until_prompt(COMMAND_TIMEOUT)
        match = PROMPT.search(text)
        prompt = match.group(1) if match else ""
        body = text[:match.start(1)] if match else text
        # The first line is the terminal echoing what was typed.
        body = body.split("\n", 1)[1] if "\n" in body else ""
        if done is None:
            return Reply(body, first or COMMAND_TIMEOUT, COMMAND_TIMEOUT, prompt, True)
        return Reply(body, first if first is not None else done, done, prompt)

    def close(self):
        self.client.close()


class WebSession:
    """The browser terminal's Socket.IO events."""

    def __init__(self, url):
        import socketio

        self.client = socketio.Client()
        self.chunks = []
        self.ended = threading.Event()
        self.first = None
        self.client.on("terminal_chunk", self._on_chunk)
        self.client.on("terminal_end", lambda *_: self.ended.set())
        self.client.connect(url)

    def _on_chunk(self, data):
        if self.first is None:
            self.first = time.perf_counter()
        self.chunks.append(data.get("chunk", ""))

    def run(self, command):
        self.chunks, self.first = [], None
        self.ended.clear()
        start = time.perf_counter()
        self.client.emit("execute_command", {"command": command})
        finished = self.ended.wait(COMMAND_TIMEOUT)
        done = time.perf_counter() - start
        first = self.first - start if self.first else done
        return Reply(clean_text("".join(self.chunks)), first, done, timed_out=not finished)

    def close(self):
        self.client.disconnect()


class WslSession:
    """A real bash shell in a throwaway WSL folder."""

    END = "__BASELINE_DONE__"

    def __init__(self, distro="Ubuntu"):
        self.process = subprocess.Popen(
            ["wsl.exe", "-d", distro, "--exec", "bash", "--noprofile", "--norc"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.run('cd "$(mktemp -d)"')

    def run(self, command):
        start = time.perf_counter()
        # Bytes, because text mode on Windows would send \r\n to bash.
        self.process.stdin.write(f"{command}\necho {self.END}\n".encode())
        self.process.stdin.flush()
        lines = []
        while True:
            line = self.process.stdout.readline().decode("utf-8", "replace")
            if not line or line.strip() == self.END:
                break
            lines.append(line)
        done = time.perf_counter() - start
        return Reply("".join(lines), done, done)

    def close(self):
        self.process.stdin.close()
        self.process.terminate()


def character_problems(command, output):
    """Reasons this output could not have come from a real machine."""
    problems = []
    # A real shell repeats the attacker's own words, as in "No manual entry for x".
    typed = command.lower()
    leaks = [m.group(0) for m in LEAK.finditer(output) if m.group(0).lower() not in typed]
    if leaks:
        problems.append("leak: " + leaks[0])
    if PROSE.search(output):
        problems.append("prose")
    if "```" in output:
        problems.append("markdown")
    if INVENTED_PROMPT.search(output):
        problems.append("invented prompt")
    first_line = output.split("\n", 1)[0].strip()
    if first_line and first_line == command.strip() and not command.startswith(("echo", "printf", "history")):
        problems.append("repeated the command")
    return problems


def check_output(check, reply, command):
    """Returns (passed, why it failed)."""
    output = reply.output
    if reply.timed_out:
        return False, "timed out"
    if "empty" in check:
        return output == "", f"expected no output, got {output[:80]!r}"
    if "exact" in check:
        return output == check["exact"], f"expected {check['exact']!r}"
    if "expected" in check:
        return output == check["expected"], f"expected {check['expected']!r}"
    if "exact_words" in check:
        return sorted(output.split()) == sorted(check["exact_words"]), \
            f"expected {check['exact_words']}"
    if "contains" in check:
        missing = [c for c in check["contains"] if c not in output]
        return not missing, f"missing {missing}"
    if "regex" in check:
        return bool(re.search(check["regex"], output)), f"no match for {check['regex']}"
    if "prompt" in check:
        return bool(re.search(check["prompt"], reply.prompt)), f"prompt was {reply.prompt!r}"
    if "clean" in check:
        problems = character_problems(command, output)
        return not problems, f"{problems}"
    return True, ""


class Run:
    def __init__(self, new_session, target):
        self.new_session = new_session
        self.target = target
        self.session = None
        self.timings = []
        self.cases = []
        self.character = []

    def start_session(self):
        self.end_session()
        self.session = self.new_session()

    def end_session(self):
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
        self.session = None

    def send(self, command, group, case_id, kind="simple"):
        """Run one command and record its timing and any character problems."""
        reply = self.session.run(command)
        self.timings.append({"id": case_id, "group": group, "cmd": command, "class": kind,
                             "at": time.time(), "first": reply.first, "done": reply.done,
                             "timed_out": reply.timed_out})
        problems = character_problems(command, reply.output)
        if problems:
            self.character.append({"id": case_id, "cmd": command, "problems": problems,
                                   "output": reply.output[:300]})
        if reply.timed_out:
            # The prompt never came back, so this session can't be trusted any more.
            self.start_session()
        return reply

    def record(self, case_id, group, score, passed, why, commands, output):
        self.cases.append({"id": case_id, "group": group, "score": score, "pass": bool(passed),
                           "why": "" if passed else why, "cmd": commands,
                           "output": str(output)[:600]})
        print(f"  {'PASS' if passed else 'FAIL'} {case_id} {commands[:60]}", flush=True)

    def step(self, step, group, score):
        kind = step.get("class", "simple")
        step_type = step.get("type", "step")
        case_id = step["id"]

        if step_type == "step":
            replies = [self.send(step["cmd"], group, case_id, kind)
                       for _ in range(step.get("times", 1))]
            if "check" in step:
                results = [check_output(step["check"], r, step["cmd"]) for r in replies]
                failed = [why for ok, why in results if not ok]
                self.record(case_id, group, score, not failed, "; ".join(failed)[:300],
                            step["cmd"], replies[-1].output)

        elif step_type == "repeat":
            outputs = [self.send(step["cmd"], group, case_id, kind).output
                       for _ in range(step["times"])]
            self.record(case_id, group, score, len(set(outputs)) == 1,
                        "output changed between runs", step["cmd"], outputs)

        elif step_type == "same":
            outputs = [self.send(c, group, case_id, kind).output for c in step["cmds"]]
            self.record(case_id, group, score, len(set(outputs)) == 1,
                        "commands disagree", " = ".join(step["cmds"]), outputs)

        elif step_type == "cross_session":
            first = self.send(step["cmd"], group, case_id, kind).output
            self.start_session()
            second = self.send(step["cmd"], group, case_id, kind).output
            self.record(case_id, group, score, first == second,
                        "new session got a different answer", step["cmd"], [first, second])

        elif step_type == "special":
            passed, why, output = SPECIAL[step["name"]](self, group, case_id)
            self.record(case_id, group, score, passed, why, step["name"], output)


def nproc_cpuinfo(run, group, case_id):
    cores = run.send("nproc", group, case_id).output
    info = run.send("cat /proc/cpuinfo", group, case_id).output
    count = len(re.findall(r"(?m)^processor\s*:", info))
    return cores.isdigit() and int(cores) == count, f"nproc {cores!r}, cpuinfo {count}", cores


def free_meminfo(run, group, case_id):
    free = run.send("free -m", group, case_id).output
    info = run.send("cat /proc/meminfo", group, case_id).output
    free_match = re.search(r"Mem:\s+(\d+)", free)
    info_match = re.search(r"MemTotal:\s+(\d+) kB", info)
    if not free_match or not info_match:
        return False, "could not read memory totals", free[:100]
    a, b = int(free_match.group(1)), int(info_match.group(1)) / 1024
    return abs(a - b) <= b * 0.02, f"free {a} MiB, meminfo {b:.0f} MiB", f"{a} / {b:.0f}"


def wc_cat(run, group, case_id):
    counted = run.send("wc -l /etc/passwd", group, case_id).output
    lines = run.send("cat /etc/passwd", group, case_id).output
    actual = len(lines.split("\n"))
    match = re.match(r"\s*(\d+) /etc/passwd$", counted)
    return bool(match) and int(match.group(1)) == actual, f"wc {counted!r}, cat {actual}", counted


def passwd_home(run, group, case_id):
    homes = run.send("ls /home", group, case_id).output.split()
    passwd = run.send("cat /etc/passwd", group, case_id).output
    missing = [h for h in homes if f":/home/{h}:" not in passwd]
    return bool(homes) and not missing, f"not in /etc/passwd: {missing or 'no homes'}", homes


def clock_moves(run, group, case_id):
    first = run.send("date +%s", group, case_id).output
    time.sleep(2)
    second = run.send("date +%s", group, case_id).output
    ok = first.isdigit() and second.isdigit() and int(second) > int(first)
    return ok, f"{first!r} then {second!r}", [first, second]


def uptime_moves(run, group, case_id):
    first = run.send("cat /proc/uptime", group, case_id).output.split()
    time.sleep(2)
    second = run.send("cat /proc/uptime", group, case_id).output.split()
    try:
        ok = float(second[0]) > float(first[0])
    except (IndexError, ValueError):
        ok = False
    return ok, f"{first} then {second}", [first, second]


def state_isolated(run, group, case_id):
    """One attacker's files must not appear for the next attacker."""
    run.send("touch only_here.txt", group, case_id)
    run.start_session()
    listing = run.send("ls", group, case_id).output
    return "only_here.txt" not in listing, "file leaked into a new session", listing


SPECIAL = {
    "nproc_cpuinfo": nproc_cpuinfo,
    "free_meminfo": free_meminfo,
    "wc_cat": wc_cat,
    "passwd_home": passwd_home,
    "clock_moves": clock_moves,
    "uptime_moves": uptime_moves,
    "state_isolated": state_isolated,
}


def network_round_trip(host, port):
    """Median TCP connect time, so network delay isn't mistaken for model delay."""
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        try:
            socket.create_connection((host, port), timeout=3).close()
            samples.append(time.perf_counter() - start)
        except OSError:
            pass
    return statistics.median(samples) if samples else None


def spread(values):
    if not values:
        return None
    ordered = sorted(values)
    return {"n": len(ordered), "median": statistics.median(ordered),
            "p95": ordered[int(0.95 * (len(ordered) - 1))], "max": ordered[-1]}


def summarise(run, cold_start, round_trip):
    by_score = {}
    for case in run.cases:
        total, passed = by_score.get(case["score"], (0, 0))
        by_score[case["score"]] = (total + 1, passed + case["pass"])
    scores = {name: {"passed": p, "total": t, "percent": round(100 * p / t, 1)}
              for name, (t, p) in by_score.items()}

    timing = {}
    for kind in ("simple", "invent"):
        rows = [t for t in run.timings if t["class"] == kind and not t["timed_out"]]
        timing[kind] = {"first_output": spread([t["first"] for t in rows]),
                        "prompt_back": spread([t["done"] for t in rows])}
    session = [t["done"] for t in run.timings if t["group"] == "attacker_session"]
    return {
        "scores": scores,
        "timing": timing,
        "attacker_session_seconds": round(sum(session), 2) if session else None,
        "timeouts": sum(t["timed_out"] for t in run.timings),
        "character_problems": len(run.character),
        "cold_start_seconds": cold_start,
        "network_round_trip_seconds": round_trip,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["ssh", "web", "wsl"], default="ssh")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--web-url", help="default: http://<host>:8000")
    parser.add_argument("--label", required=True)
    parser.add_argument("--only", help="comma-separated group names")
    args = parser.parse_args()

    data = json.loads((HERE / "commands.json").read_text(encoding="utf-8"))
    web_url = args.web_url or f"http://{args.host}:8000"
    factories = {
        "ssh": lambda: SSHSession(args.host, args.ssh_port),
        "web": lambda: WebSession(web_url),
        "wsl": WslSession,
    }

    groups = data["groups"]
    if args.only:
        groups = [g for g in groups if g["name"] in args.only.split(",")]
    if args.target == "wsl":
        groups = [g for g in groups if g.get("local_safe")]
    if args.target != "ssh":
        groups = [g for g in groups if not g.get("ssh_only")]

    round_trip = None
    if args.target != "wsl":
        round_trip = network_round_trip(args.host, args.ssh_port)
        print(f"network round trip: {round_trip}")

    run = Run(factories[args.target], args.target)
    cold_start = None
    started = time.time()
    if args.target != "wsl":
        run.start_session()
        cold_start = run.send(data["cold_start_command"], "cold_start", "COLD").done
        print(f"cold start: {cold_start:.2f}s")

    for group in groups:
        print(f"== {group['name']}", flush=True)
        run.start_session()
        for step in group["steps"]:
            run.step(step, group["name"], group["score"])
    run.end_session()

    summary = summarise(run, cold_start, round_trip)
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"{args.label}.json"
    out.write_text(json.dumps({
        "label": args.label, "target": args.target, "host": args.host,
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "minutes": round((time.time() - started) / 60, 1),
        "summary": summary, "cases": run.cases, "timings": run.timings,
        "character": run.character,
    }, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    failed = [c for c in run.cases if not c["pass"]]
    print(f"\n{len(failed)} of {len(run.cases)} checks failed; saved to {out}")
    for case in failed:
        print(f"  {case['id']} {case['cmd'][:50]}: {case['why'][:100]}")


if __name__ == "__main__":
    main()
