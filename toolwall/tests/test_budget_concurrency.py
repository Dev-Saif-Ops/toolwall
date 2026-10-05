"""Budgets must hold when one Gate is shared across threads (2026-10-05 red-team).

The budget was read at check time and only incremented at execute time, with
shield scanning, copying and hashing in between. 32 threads against
max_calls=1 executed the tool up to 24 times.
"""

import threading

import pytest

from toolwall import Gate, Shield, ToolSchema, Verdict


def hammer(gate, payload, threads=32):
    barrier = threading.Barrier(threads)
    results = []

    def worker():
        barrier.wait()
        results.append(gate.run(payload))

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return results


@pytest.mark.parametrize("budget", [{"max_calls": 1}, {"max_calls_per_tool": 1}, {"max_calls": 3}])
def test_shared_gate_never_exceeds_budget(budget):
    ran = []
    gate = Gate(default="deny", shield=Shield(mode="block"))
    gate.register("tool", lambda pad: ran.append(1), schema=ToolSchema(required=["pad"]))
    gate.budget(**budget)
    cap = next(iter(budget.values()))
    # A large argument widens the old check-to-execute window.
    results = hammer(gate, {"name": "tool", "args": {"pad": "x " * 100_000}})
    assert len(ran) == cap
    assert sum(r.executed for r in results) == cap
    refused = [r for r in results if not r.executed]
    assert all(r.verdict is Verdict.BLOCK for r in refused)
    assert all("budget exceeded" in " ".join(r.reasons) for r in refused)


def test_refused_replay_does_not_rewrite_the_executed_result():
    ran = []
    gate = Gate(default="deny")
    gate.register("tool", lambda id: ran.append(id), schema=ToolSchema(required=["id"]))
    first = gate.run({"name": "tool", "args": {"id": 1}})
    again = gate.execute(first)
    assert ran == [1]
    assert again is not first
    assert again.verdict is Verdict.BLOCK
    assert first.verdict is Verdict.ALLOW and first.executed  # history stays true
    assert gate.report()["verdicts"].get("allow") == 1
