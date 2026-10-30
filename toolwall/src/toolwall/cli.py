"""toolwall CLI: a no-key demo, approval tickets, and inspecting meter/audit exports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_report(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    summary = data.get("summary") or {}
    print(f"Model:  {data.get('model', 'unknown')}")
    print(f"Events: {summary.get('event_count', len(data.get('events', [])))}")
    for lane, stats in (summary.get("lanes") or {}).items():
        print(f"\n[{lane}]")
        for key in (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "estimated_cost_usd",
            "intercept_success_rate",
        ):
            print(f"  {key}: {stats.get(key)}")
    if summary.get("note"):
        print(f"\nNote: {summary['note']}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from toolwall.demo import run_demo

    return run_demo(color=False if args.no_color else None)


def cmd_approvals(args: argparse.Namespace) -> int:
    from toolwall.approvals import Approvals, SQLiteStore, TicketError

    if not Path(args.db).is_file():
        print(f"no approvals database at {args.db}", file=sys.stderr)
        return 2
    import sqlite3

    try:
        store = SQLiteStore(args.db)
    except sqlite3.DatabaseError as exc:
        print(f"{args.db} isn't an approvals database: {exc}", file=sys.stderr)
        return 2
    approvals = Approvals(store)
    try:
        if args.action == "list":
            tickets = approvals.pending() if not args.all else approvals.store.list()
            if not tickets:
                print("No tickets waiting." if not args.all else "No tickets.")
            for t in tickets:
                print(f"{t.id}  {t.status:<8}  {t.tool}({json.dumps(t.args, sort_keys=True)})"
                      f"  context={json.dumps(t.context, sort_keys=True)}")
            return 0
        if not args.ticket:
            print(f"say which ticket: toolwall approvals {args.action} TICKET", file=sys.stderr)
            return 2
        if args.action == "show":
            t = approvals.get(args.ticket)
            if t is None:
                print(f"no ticket {args.ticket!r}", file=sys.stderr)
                return 1
            print(json.dumps({k: getattr(t, k) for k in t.__dataclass_fields__}, indent=2,
                             sort_keys=True))
            return 0
        if not args.by:
            print("say who decides: --by you@example.com", file=sys.stderr)
            return 2
        decide = approvals.approve if args.action == "approve" else approvals.deny
        t = decide(args.ticket, by=args.by, note=args.note)
        print(f"{t.id} {t.status} by {t.decided_by}")
        return 0
    except TicketError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        store.close()


def main() -> None:
    ap = argparse.ArgumentParser(prog="toolwall", description="toolwall dev tools")
    sub = ap.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Watch the gate stop a support agent's bad tool calls (no API key)")
    demo.add_argument("--no-color", action="store_true", help="Plain output")
    demo.set_defaults(func=cmd_demo)

    report = sub.add_parser("report", help="Print summary from a Meter JSON export")
    report.add_argument("file", help="Path to meter/audit JSON")
    report.set_defaults(func=cmd_report)

    appr = sub.add_parser("approvals", help="List, approve or deny approval tickets in a SQLite store")
    appr.add_argument("action", choices=["list", "show", "approve", "deny"])
    appr.add_argument("ticket", nargs="?", help="Ticket id (tkt_...)")
    appr.add_argument("--db", required=True, help="Path to the SQLiteStore file")
    appr.add_argument("--by", help="Who is deciding (recorded on the ticket)")
    appr.add_argument("--note", help="Why (recorded on the ticket)")
    appr.add_argument("--all", action="store_true", help="list: every ticket, not just pending")
    appr.set_defaults(func=cmd_approvals)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
