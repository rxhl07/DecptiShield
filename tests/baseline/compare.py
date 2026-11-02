"""
Compare two saved runs and list anything that got worse.

Usage: python compare.py baseline tuned
"""
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"


def load(label):
    return json.loads((RESULTS / f"{label}.json").read_text(encoding="utf-8"))


def seconds(value):
    return "-" if value is None else f"{value:.2f}s"


def row(name, before, after):
    print(f"{name:<34}{before:>14}{after:>14}")


def main():
    a_label, b_label = sys.argv[1], sys.argv[2]
    a, b = load(a_label), load(b_label)
    sa, sb = a["summary"], b["summary"]

    row("", a_label, b_label)
    for name in ("accuracy", "consistency", "character"):
        x, y = sa["scores"].get(name), sb["scores"].get(name)
        row(f"{name} %", f"{x['percent']}" if x else "-", f"{y['percent']}" if y else "-")
    row("character problems", str(sa["character_problems"]), str(sb["character_problems"]))
    row("timeouts", str(sa["timeouts"]), str(sb["timeouts"]))
    row("cold start", seconds(sa["cold_start_seconds"]), seconds(sb["cold_start_seconds"]))
    row("attacker session total", seconds(sa["attacker_session_seconds"]),
        seconds(sb["attacker_session_seconds"]))

    for kind, title in (("simple", "predictable commands"), ("invent", "invented output")):
        for measure, label in (("first_output", "first output"), ("prompt_back", "prompt back")):
            x, y = sa["timing"][kind][measure], sb["timing"][kind][measure]
            for stat in ("median", "p95"):
                row(f"{title}, {label} {stat}",
                    seconds(x[stat] if x else None), seconds(y[stat] if y else None))

    before = {c["id"]: c for c in a["cases"]}
    after = {c["id"]: c for c in b["cases"]}
    worse = [i for i in before if i in after and before[i]["pass"] and not after[i]["pass"]]
    better = [i for i in before if i in after and not before[i]["pass"] and after[i]["pass"]]

    print(f"\nfixed: {len(better)}  {' '.join(better)}")
    print(f"got worse: {len(worse)}")
    for case_id in worse:
        print(f"  {case_id} {after[case_id]['cmd'][:50]}: {after[case_id]['why'][:100]}")
    still = [c for c in after.values() if not c["pass"]]
    print(f"still failing: {len(still)}  {' '.join(c['id'] for c in still)}")
    sys.exit(1 if worse else 0)


if __name__ == "__main__":
    main()
