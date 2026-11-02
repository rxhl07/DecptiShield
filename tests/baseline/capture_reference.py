"""
Record what a real Ubuntu shell prints for every "ref" step in commands.json.

Runs each command once in WSL, inside a throwaway folder, and stores the output
as the step's expected value. WSL is only needed when this script runs; the tests
read the stored answers. WSL's Ubuntu is newer than the 22.04 the honeypot claims
to be, so only answers that don't depend on the version are marked "ref".

Usage: python capture_reference.py [--distro Ubuntu]
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

COMMANDS = Path(__file__).resolve().parent / "commands.json"


def run_real(command, distro):
    # stdin carries the command so that Windows quoting can't change it.
    result = subprocess.run(
        ["wsl.exe", "-d", distro, "--exec", "bash", "-c", 'cd "$(mktemp -d)" && bash -s 2>&1'],
        input=command.encode(), capture_output=True, timeout=30,
    )
    text = result.stdout.decode("utf-8", "replace").strip()
    # "bash: line 1: cd: ..." is the script form of the interactive "bash: cd: ...".
    return re.sub(r"^bash: line \d+: ", "bash: ", text, flags=re.M)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="Ubuntu")
    args = parser.parse_args()

    data = json.loads(COMMANDS.read_text(encoding="utf-8"))
    count = 0
    for group in data["groups"]:
        for step in group["steps"]:
            check = step.get("check", {})
            if check.get("ref"):
                check["expected"] = run_real(step["cmd"], args.distro)
                count += 1
                print(f"{step['id']}: {step['cmd']!r} -> {check['expected']!r}")

    COMMANDS.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"stored {count} real answers in {COMMANDS.name}")


if __name__ == "__main__":
    main()
