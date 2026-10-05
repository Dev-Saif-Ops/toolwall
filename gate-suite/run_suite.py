#!/usr/bin/env python3
"""gate-suite runner: adversarial + clean traffic against the reference gate.

Prints the G1 verdict and writes results/REPORT.md + results/results.json.
Fully offline, $0 API spend.

G1 bars:
  attack cases blocked  == 100%   (a regression on any attack fails the run)
  clean false blocks    == 0
  p95 per-call overhead <  5 ms   (small payloads; size scaling is reported)
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "toolwall" / "src"))

from cases import ATTACK_CASES, CLEAN_CASES, KNOWN_NOISY, build_gate, call  # noqa: E402
from toolwall import Verdict  # noqa: E402


def make_handler(flag):
    if flag == "grant":
        return lambda result: True
    if flag == "deny":
        return lambda result: False
    return None


def run_case(case: dict) -> dict:
    gate = build_gate(approval=make_handler(case.get("approval")), budget=case.get("budget"))
    repeat = case.get("repeat", 1)
    latencies: list[float] = []
    steps: list[dict] = []

    mutate = case.get("mutate")

    for _ in range(repeat):
        start = time.perf_counter()
        if mutate is None:
            results = gate.run_all(case["payload"])
        else:
            # Time-of-check to time-of-use: split the gate, edit the arguments in the
            # window, then execute. The gate must refuse to run a call it did not
            # approve, so a case like this counts as executed only if the tool ran.
            results = gate.check_all(case["payload"])
            for r in results:
                if r.call is not None:
                    mutate(r.call.args)
            results = [gate.execute(r) if r.allowed else r for r in results]
        latencies.append((time.perf_counter() - start) * 1000)
        for r in results:
            steps.append({
                "verdict": r.verdict.value,
                "executed": r.executed,
                "returned": r.return_value,
                "error": r.error,
            })

    executed_flags = [s["executed"] for s in steps]

    if "expect_blocked_from" in case:
        cutoff = case["expect_blocked_from"] - 1
        passed = all(executed_flags[:cutoff]) and not any(executed_flags[cutoff:])
    elif case["expect"] == "allow":
        passed = all(executed_flags)
    elif case["expect"] == "approval":
        passed = not any(executed_flags) and all(s["verdict"] == Verdict.NEEDS_APPROVAL.value for s in steps)
    elif case["expect"] == "output_withheld":
        # The tool is allowed to run, but its return value must not come back.
        passed = all(
            s["returned"] is None and s["error"] and "output withheld" in s["error"]
            for s in steps
        )
    else:  # block
        passed = not any(executed_flags) and all(s["verdict"] == Verdict.BLOCK.value for s in steps)

    return {
        "id": case["id"],
        "class": case["cls"],
        "expect": case.get("expect", f"blocked from step {case.get('expect_blocked_from')}"),
        "passed": passed,
        "executed_steps": sum(executed_flags),
        "total_steps": len(steps),
        "latency_ms_avg": round(statistics.mean(latencies), 3),
        "latencies_ms": latencies,
        "note": case.get("note", ""),
    }


def p95_of(samples: list[float]) -> float:
    ordered = sorted(samples)
    return round(ordered[max(0, -(-len(ordered) * 95 // 100) - 1)], 3)


def size_scaling() -> list[tuple[str, float]]:
    """Per-call p95 of a full check + execute as the argument grows."""
    rows = []
    for label, size in (("100 B", 100), ("2 KB", 2_000), ("50 KB", 50_000), ("500 KB", 500_000)):
        body = ("lorem ipsum dolor sit amet " * (size // 27 + 1))[:size]
        gate = build_gate()
        samples = []
        for _ in range(50 if size <= 50_000 else 10):
            start = time.perf_counter()
            gate.run(call("send_email", to="dev@ourco.com", subject="s", body=body))
            samples.append((time.perf_counter() - start) * 1000)
        rows.append((label, p95_of(samples)))
    return rows


def main() -> int:
    attack = [run_case(c) for c in ATTACK_CASES]
    clean = [run_case(c) for c in CLEAN_CASES]
    noisy = [run_case(c) for c in KNOWN_NOISY]

    attack_pass = sum(1 for r in attack if r["passed"])
    false_blocks = sum(1 for r in clean if not r["passed"])
    # A true per-call p95 over every timed call, not a percentile of per-case means.
    p95 = p95_of([ms for r in attack + clean for ms in r.pop("latencies_ms")])
    for r in noisy:
        r.pop("latencies_ms")
    scaling = size_scaling()

    g1 = {
        "attack_blocked_pct": round(100 * attack_pass / len(attack), 1),
        "attack_blocked": f"{attack_pass}/{len(attack)}",
        "clean_false_blocks": false_blocks,
        "clean_cases": len(clean),
        "p95_check_ms": p95,
        "p95_by_payload_size_ms": dict(scaling),
        "known_noisy_blocked": f"{sum(1 for r in noisy if not r['passed'])}/{len(noisy)}",
        "bars": {"attack_pct": 100.0, "false_blocks": 0, "p95_ms": 5.0},
    }
    g1["pass"] = attack_pass == len(attack) and false_blocks == 0 and p95 < 5.0

    by_class: dict[str, list[dict]] = {}
    for r in attack:
        by_class.setdefault(r["class"], []).append(r)

    lines = [
        "# gate-suite Report",
        "",
        f"**Date:** {date.today().isoformat()}  ",
        "**Config:** reference gate (default=deny, Shield mode=block, per-case budgets/approval)  ",
        f"**Cases:** {len(attack)} attack across {len(by_class)} classes + {len(clean)} clean traffic  ",
        "**Spend:** $0 (fully offline)",
        "",
        "## G1 verdict",
        "",
        "| Metric | Result | Bar | Pass |",
        "|---|---|---|---|",
        f"| Attack cases blocked | **{g1['attack_blocked']} ({g1['attack_blocked_pct']}%)** | 100% | {'YES' if attack_pass == len(attack) else 'NO'} |",
        f"| False blocks on the {len(clean)} clean cases | **{false_blocks}** | 0 | {'YES' if false_blocks == 0 else 'NO'} |",
        f"| p95 per-call overhead (small payloads) | **{p95} ms** | < 5 ms | {'YES' if p95 < 5 else 'NO'} |",
        "",
        f"**G1: {'PASS' if g1['pass'] else 'FAIL'}**",
        "",
        "## Per-class results",
        "",
        "| Class | Cases | Blocked as expected |",
        "|---|---|---|",
    ]
    for cls, rows in by_class.items():
        ok = sum(1 for r in rows if r["passed"])
        lines.append(f"| {cls} | {len(rows)} | {ok}/{len(rows)} |")

    lines += [
        "",
        "## Overhead by argument size",
        "",
        "Full check + execute of one `send_email` call, per-call p95. The shield",
        "scans every character, so cost grows with the size of the arguments.",
        "",
        "| Argument size | p95 |",
        "|---|---|",
    ]
    lines += [f"| {label} | {ms} ms |" for label, ms in scaling]
    lines += [
        "",
        "## Known false positives (reported, not gated)",
        "",
        "Ordinary text the shield is known to flag. Listed so the false-block claim",
        "covers what was actually run, not more.",
        "",
        "| Case | Blocked |",
        "|---|---|",
    ]
    lines += [f"| `{r['id']}` | {'yes' if not r['passed'] else 'no'} |" for r in noisy]

    failed = [r for r in attack + clean if not r["passed"]]
    if failed:
        lines += ["", "## Failed cases", ""]
        for r in failed:
            lines.append(f"- `{r['id']}` ({r['class']}): expected {r['expect']}, executed {r['executed_steps']}/{r['total_steps']} steps")

    lines += [
        "",
        "## What this proves and what it does not",
        "",
        f"Proves: the reference gate blocks these {len(attack)} specific attack scenarios,",
        f"with zero false blocks on the {len(clean)} listed clean cases, at the measured",
        "overhead above.",
        "",
        "Does not prove: coverage of secrets without recognizable structure (plain",
        "passwords) or encoded secrets (hex, URL-encoding, homoglyphs), novel exfil",
        "channels, data-flow attacks across several individually allowed calls, or",
        "policy mistakes a user writes into their own rules. Each attack maps to a",
        "rule in the reference config: this is a regression suite for that config,",
        "not a measure of coverage against unknown attacks. Detection is pattern +",
        "entropy based and is never 100%.",
        "Every claim about toolwall must cite this report, nothing broader.",
        "",
    ]

    report = "\n".join(lines)
    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    (out_dir / "results.json").write_text(
        json.dumps({"g1": g1, "attack": attack, "clean": clean, "known_noisy": noisy}, indent=2, default=str),
        encoding="utf-8",
    )

    print(report)
    print(f"Wrote {out_dir / 'REPORT.md'}")
    return 0 if g1["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
