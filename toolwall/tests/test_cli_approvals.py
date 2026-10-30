"""`toolwall approvals`: the CLI approver for a SQLiteStore."""

import os
import pathlib
import subprocess
import sys

import toolwall
from toolwall import Approvals, SQLiteStore, ToolWall

# Run the CLI from the same toolwall these tests import.
SRC = str(pathlib.Path(toolwall.__file__).resolve().parent.parent)


def cli(*argv):
    env = dict(os.environ, PYTHONPATH=SRC)
    p = subprocess.run([sys.executable, "-m", "toolwall", "approvals", *argv],
                       capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def test_list_approve_and_run(tmp_path):
    db = str(tmp_path / "a.db")
    wall = ToolWall(approvals=Approvals(SQLiteStore(db)))
    ran = []

    @wall.protect
    def wire(amount: int) -> str:
        ran.append(amount)
        return "ok"

    wall.rule("wire", require_approval=True)
    ticket = wall.call("wire", {"amount": 5}).ticket
    code, out = cli("list", "--db", db)
    assert code == 0 and ticket in out and '"amount": 5' in out
    assert cli("approve", ticket, "--db", db)[0] == 2              # --by is required
    code, out = cli("approve", ticket, "--db", db, "--by", "ops@ourco.com")
    assert code == 0 and "approved" in out
    assert cli("approve", ticket, "--db", db, "--by", "ops")[0] == 1  # not pending any more
    assert wall.run_approved(ticket).allowed and ran == [5]
    code, out = cli("show", ticket, "--db", db)
    assert code == 0 and '"status": "used"' in out
    wall.approvals.store.close()


def test_missing_database_is_an_error(tmp_path):
    code, out = cli("list", "--db", str(tmp_path / "nope.db"))
    assert code == 2 and not (tmp_path / "nope.db").exists()
