# Contributing to toolwall

Thanks for looking. This is an early project, and outside input is genuinely
useful right now, especially on threat models.

## What is most wanted

**Threat models and attack cases.** The most valuable contribution is a
concrete scenario where toolwall lets something through that it should not.
Open an issue with the tool definitions, the call sequence, and what you expect
the verdict to be. If it is real, it becomes a case in `gate-suite/`.

**Design discussion on open issues.** Some issues are design tracks with no
implementation yet. Comments there are contributions.

**Framework recipes.** A short, working example of wiring toolwall into
LangGraph, CrewAI, an OpenAI Agents SDK app, or anything else.

**Bug reports.** Especially anything where the gate raises an exception instead
of returning a verdict. A crash is not a verdict, and that is a bug every time.

## The one invariant

Everything rests on this:

> If the verdict is not `ALLOW`, the underlying callable never runs.

`toolwall/tests/test_invariant_fuzz.py` asserts it against 2000 generated
payloads per mode. Any change that breaks it is wrong, no matter what else it
improves. Any change that makes the gate raise instead of returning a verdict is
also wrong, because the caller's error handling then decides what happens, which
is not fail closed.

## Running things

Requires Python 3.10+. The package itself has no runtime dependencies.

```bash
cd toolwall
pip install -e ".[dev]"
python -m pytest -q
```

Currently 155 tests.

The attack suite is separate, and it is what every public claim about toolwall
cites:

```bash
cd gate-suite
python run_suite.py
```

Currently 28/28 attack cases blocked with zero executions, and every clean case
executes. **A change that blocks legitimate traffic fails the suite just as hard
as one that lets an attack through.** False blocks are the main reason security
tooling gets removed.

## Pull requests

- Open an issue first for anything beyond a small fix, so the design is agreed
  before you spend time on it.
- One concern per PR.
- New behaviour needs a test. Security-relevant behaviour needs a `gate-suite`
  case as well.
- Do not add runtime dependencies. Zero dependencies is a deliberate constraint,
  since this library sits in the execution path of other people's agents.
- Match the surrounding style. No formatter is enforced.

## Claims

This project tries hard not to overstate what it does. If a change adds a
capability, the README claim for it must be backed by a suite case that proves
it. If it is not proven, it does not get claimed. The `REPORT.md` the suite
writes includes a "does not prove" section, and that section is as important as
the pass rate.

## License

Contributions are accepted under the MIT license, the same license as the
project. There is no CLA. By opening a pull request you agree your contribution
is licensed under MIT.

## Security issues

A bypass (a call or secret that gets through the documented configuration, or
the gate failing open) is reported privately, not as an issue. See
[SECURITY.md](SECURITY.md) for how, what counts, and what happens next. False
blocks, crashes where nothing executes, and new suite ideas are fine as public
issues.
