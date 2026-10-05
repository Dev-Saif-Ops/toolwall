# Changelog

## [0.4.2] - 2026-10-05

Findings from a three-lens red-team (bypass hunting, claims and mutation
testing, a first-time user wiring a live local agent). Every fix below has a
test that fails on 0.4.1.

### Security
- **Output secrets leaked in common shapes.** The shield only walked str, dict
  values and lists. Database rows from `fetchall()` (tuples), sets, bytes,
  dataclasses, driver row objects, other objects, and secrets used as dict keys
  passed through unscanned, in arguments and in return values. The walker now
  covers all of these, iteratively and cycle-safe; redaction keeps container
  types and covers keys.
- **Output scanning failed open.** A scan that raised left the unscanned return
  value in place. It is now withheld. Lazy iterables (generators, `map`, database
  cursors, file objects, ORM query sets: anything iterable that is not a plain
  container) are withheld too, because their `str()` says nothing about what they
  will yield. So are other iterable objects the shield cannot read whole: an XML
  `Element` (its `keys()` lists attributes, not text), pydantic models, numpy
  arrays. **Rule of thumb: return plain, materialised data** (dicts, lists,
  tuples, `fetchall()` rows, `model_dump()`, `tolist()`). The output shield is
  defence in depth for that plain data, not a scanner for arbitrary objects. Row-like objects such as email messages are scanned
  through their attributes and `str()` as well as `keys()`; classes and functions
  are scanned through `str()` (a forgotten `()` returns a bound method that prints
  its record). The walker holds every visited object so a reused `id()` cannot make
  it skip one. A withheld output's reason no longer echoes the output's keys.
- **Redaction never touches the tool's data.** Only the parts of a value that held
  a secret are rebuilt, through constructors (OrderedDict, defaultdict and Counter
  keep their type and values; other mappings become a plain dict). Everything
  else comes back as the tool's own object. Never copy-and-refill: a mapping that
  is a view over real storage (`os.environ`, a shelve file) would be written to. A tool's exception text is scanned before
  it reaches the model or the audit log.
- **Secrets reached the audit log through reasons.** "unknown tool", "Unexpected
  arg", argument paths and cross-rule messages echoed model-chosen text verbatim
  into reasons, the report and the JSON/CSV export. All of them are scrubbed.
- **MCPGuard bypassed execute-time controls.** It called `check()` and then the
  forward function directly: no budget, dry-run still forwarded, no output scan,
  no receipt check. It now forwards through `Gate.execute(result, invoke=...)`.
- **`in_range` accepted NaN** (and `"nan"`, `Decimal("NaN")`), and the test that
  claimed to cover it never reached the policy. Non-finite values and bools are
  now out of range, and NaN/Infinity literals in argument JSON are an intake error.
- **Budgets did not hold on a shared Gate.** The budget was read at check time and
  incremented at execute time; 32 threads against `max_calls=1` ran the tool up to
  24 times. `execute()` now re-checks and reserves the slot atomically.
- **The recommended recipient rule was bypassable.** `ends_with("@ourco.com")`
  passes `"attacker@evil.com,ops@ourco.com"`. New `email_domain()` accepts one bare
  address on an exact domain and rejects `%`/`!` source routing; examples and the
  suite use it.
- **Execution trusted fields on a mutable result.** Code holding a result (an
  approval handler included) could edit the arguments and clear `receipt`, or
  rename the call to another tool, and have that run; a hand-built
  `GateResult(ALLOW, ...)` also ran. The gate now keeps its own record of every
  result it issues (tool name and receipt at check time). `execute()` runs only a
  result it issued, only once, only for the tool that was checked, and checks the
  arguments against the recorded receipt. A held call becomes runnable only
  through a granted approval, so flipping `result.verdict` on a held or denied
  result does nothing. Single use now covers `receipt=False` tools too (their
  replay was a documented limitation). Records are weakly held and freed with
  their results.

### Changed
- Anything that raises while checking a call (deep nesting, hostile objects) is a
  BLOCK instead of an exception. Malformed provider envelopes in `run_all` can
  still raise; that is next.
- Known new false-positive class: email messages with base64 attachments trip
  the entropy check and are withheld (block) or replaced (redact).
- `in_range` no longer accepts `True`/`False` as numbers. Callers passing bools
  to a range rule will now see a block.
- Execute-time refusals return a new BLOCK result instead of rewriting the ALLOW,
  so history never says an executed call was blocked.
- gate-suite: 100% pass bar (was 90%), true per-call p95, overhead by argument
  size, seven new attacks and three new clean cases, and a published list of
  known false positives. 155 to 245 tests.

### Docs
- Fixed a paragraph spliced into the middle of a README sentence.
- Scoped the false-block and latency claims to what the suite measures.
- Documented approvals, `matches()` being a full match, and that no MCP transport
  ships yet.

## [0.4.1] - 2026-08-29

### Security
- **A third mutation window, found by the same reviewer within the hour.** In 0.4.0
  the execute-time hash was computed over the live args object and the tool was then
  invoked with that same live object. After the hash passed, another thread holding
  the GateResult could still mutate what the tool was reading: the receipt proved
  the past, not the call. execute() now deep-freezes the arguments, fingerprints the
  frozen copy, and invokes the tool with that same frozen copy, which is never
  reachable through the GateResult. A mid-execution mutation of `call.args` no
  longer touches what the tool sees (threaded regression test per the reviewer's
  barrier spec).
- **Single-use enforcement had a race.** Two threads handing in the same approved
  result could both pass the spent check before either set it. The check-and-set is
  now atomic under the gate lock; a concurrent double-execute runs the tool exactly
  once (regression test with a start barrier).
## [0.4.0] - 2026-08-29

One externally reported security fix, plus two defects found while writing the
onboarding docs: walking the path a first-time user actually takes turned up two
places where the gate raised instead of deciding.

Minor version bump because two behaviours changed: inferred schemas now reject
unexpected arguments, and an ALLOW is now bound to the exact arguments that were
checked (mutated or replayed results refuse to run). Both changes are strictly
in the blocking direction; nothing previously blocked is now allowed.

### Security
- **A checked call could be edited before it ran (TOCTOU).** Reported on Reddit by
  u/deelight_0909, reproduced on two separate paths before fixing. The gate returned
  ALLOW for a specific set of arguments and then executed whatever the arguments
  happened to be at execution time. The caller still held a reference to the dict it
  passed in, so it could widen a `delete_records` filter to `{}` after the verdict;
  separately, an approval handler is given the `GateResult` itself and could rewrite
  `call.args` in the same window. The core invariant (a non-ALLOW verdict never runs
  the tool) always held, but the matching promise, that an ALLOW runs the call that
  was actually checked, did not.

  Two changes, because either one alone leaves a window open:
  - The gate now deep-copies arguments at check time, so it owns what it validated
    and the caller's reference no longer reaches the tool.
  - `check()` binds a receipt: a SHA-256 fingerprint over the tool name and a
    canonical form of the arguments. `execute()` recomputes it and refuses to run on
    a mismatch, without spending budget. The snapshot alone would not close the
    approval window, since there the gate's own copy is what gets mutated.

  Arguments that cannot be canonicalised now BLOCK by default, because running them
  unchecked would leave exactly the strangest calls unprotected. Register with
  `receipt=False` to opt a tool out explicitly and accept that its arguments are not
  tamper-checked; a `replace=True` re-registration clears any previous opt-out.

  `gate-suite` grew an eleventh class, `toctou`: **28/28 blocked, 0 false blocks.**

  The canonicaliser covers `datetime`, `date`, `time`, `Decimal`, `UUID` and `Enum`
  as well as the JSON types, because those are ordinary things to pass a booking or
  payment tool and blocking them would be a false block caused by the canonicaliser
  being unfinished rather than by anything being unsafe. Found by probing with
  realistic arguments before release, not reported. Enum members are tagged with
  their class, so an `IntEnum` cannot fingerprint as its integer value; Decimal
  keeps its exponent, which can only ever refuse a swap, never admit one. A clean
  suite case now passes `datetime` and `Decimal` args so the zero-false-blocks
  claim covers them.

### Fixed
- **A wrong budget type crashed the gate instead of failing at configuration.**
  `gate.budget(max_calls_per_tool={"tool": 5})` was accepted silently and then
  raised `TypeError` from inside `check()` on the next call, so the exception
  escaped the gate rather than producing a verdict. `budget()` now validates its
  arguments where the mistake is made, with an error that says budgets apply to
  every tool. Negative values are rejected too. (Per-tool limits are a single cap
  across all tools; a dict is not supported and now says so.)
- **An inferred schema let a hallucinated argument through.**
  `schema_from_signature()` set `allow_extra=True`, so an argument the model
  invented passed the schema and then raised `TypeError` inside the tool. That
  landed as `verdict=allow, executed=False, error=...`, which is not a statement
  about whether the call was permitted. Inferred schemas now reject unexpected
  arguments, because the signature already says exactly what the callable accepts.
  A callable declaring `**kwargs` still allows extras, since it genuinely takes
  arguments we cannot enumerate. This is a behaviour change for
  `schema_from_signature()` and `register(..., infer_schema=True)`; a
  hand-written `ToolSchema` is unaffected and still defaults to `allow_extra=True`.

### Added
- `ToolSchema.optional`: known-but-not-required argument names. Only consulted
  when `allow_extra=False`, so an optional parameter with no type annotation (and
  therefore absent from `types`) is not mistaken for an unexpected argument.
- Tests grown to 152.

## [0.3.2] - 2026-08-29

### Fixed
- **A non-string tool name crashed the gate instead of blocking (security).** Every
  provider envelope extractor validated the tool name by truthiness only, so a name
  that was a dict, list, or number reached the registry lookup and raised
  `TypeError` *out of* the gate. A crash is not a verdict: the exception escapes and
  the caller's error handling decides what happens, which is not fail-closed. Tool
  names are now validated at intake; a bad name is an `IntakeError`, which the gate
  already turns into a BLOCK. Found by the new fuzz suite on its first run.

### Added
- **Property-based fuzzing of the core invariant** (`tests/test_invariant_fuzz.py`):
  2000 generated payloads per shield mode asserting that a non-ALLOW verdict never
  results in the tool running. Generators cover nested structures, empty values,
  huge ints, NaN/inf, unicode and homoglyphs, unserializable objects, wrong types,
  all four provider shapes, and lookalike tool names. Fixed seed, stdlib only, no
  new test dependency. Also asserts budgets hold under arbitrary payload streams
  with approvals always granted, that dry-run executes nothing, and that NaN/inf
  cannot read as "in range".
- Tests grown to 125.

## [0.3.1] - 2026-08-28

### Fixed
- **Budget bypass with parallel tool calls (security).** `run_all()` checked every
  call in a payload before executing any of them, so N parallel calls all saw the
  same budget counters and all passed. A `max_calls=1` budget could execute 3 calls.
  `run_all()` now checks and executes one call at a time, so counters advance
  between calls. Regression tests added for both `max_calls` and
  `max_calls_per_tool`. Reported by a reviewer; confirmed and fixed same day.
- Budget counter reads and writes are now guarded by a lock. A `Gate` is still
  intended for one agent execution context; `check_all()` documents that checking
  many calls without executing them does not advance budget state.
- **Silent tool replacement.** Registering a name twice overwrote the first tool
  (and could leave a stale policy attached). Re-registration now raises unless
  `replace=True`, and a replace drops the previous schema/policy so a new tool
  can never inherit constraints written for the old one.

### Added
- **Tool output scanning.** The shield only ever saw tool *arguments*, so a tool
  that read a secret out of a database or file handed it straight back to the
  model. Return values now get the same treatment: `block` withholds the value,
  `redact` substitutes placeholders, `warn` records findings. Disable with
  `Shield(scan_output=False)`. Output findings are tagged `return.*` and, like all
  findings, never carry the value.
- Attack suite grew a tenth class, `output-exfil`: **25/25 blocked, 0 false blocks**.
- Tests grown to 110.

## [0.3.0] - 2026-08-28

### Added
- `ToolWall`: an ergonomic facade over `Gate`, now the primary entry point.
  `ToolWall()` wires a Gate with a Shield and Meter already attached; use
  `.register(...)`, `.call(name, args)`, `.guard(response)`, `.dry_run`,
  `.report()`, `.export()`. `Gate` remains the low-level primitive.
- `GateResult.blocked`, `.needs_approval`, and `.reason` convenience properties.
- 12 new tests (97 total).

### Changed
- Problem-led positioning across both READMEs ("The security gateway for AI
  agent tool calls"), attack-example blocks, expanded PyPI keywords for
  discovery (ai-agent-security, mcp-firewall, prompt-injection, ...).

## [0.2.2] - 2026-08-28

Docs release: brings the PyPI page in sync with the repo.

### Changed
- Both READMEs gained a step-by-step "How to use" flow and an "Examples" section
  listing all four example scripts, including the live Gemini agent
  (`examples/live_gemini_agent.py`). Repo renamed to `toolwall`; all links updated.
  No code changes; 85 tests unchanged.

## [0.2.1] - 2026-08-28

Docs-only release to give the PyPI project page a proper landing description.

### Changed
- Rich PyPI-facing README (`toolwall/README.md`): badges, problem statement,
  quickstart, feature list, dry-run + MCP examples, honest-status section, links.
  No code changes; 85 tests unchanged. (PyPI descriptions are per-release, so a
  version bump is required to refresh the page.)

## [0.2.0-dev] - 2026-08-28 — Pivot: TOAP → toolwall

### Why
TOAP's compression thesis failed an honest re-measurement: vs minified JSON it was
+4.6% tokens (o200k) / +11.1% (cl100k); vs native function-calling arguments +56%.
The ~45% claim traced to an `indent=2` baseline. Our own PRD kill criterion
("net < 25% → sell reliability/security, not cost") was met, so we honored it.
Full postmortem: `toap-v0.1-archive` branch README.

### Added
- `toolwall` package: fail-closed firewall for agent tool calls
- `intake.py`: OpenAI (chat + responses), Anthropic, Gemini, and plain-dict tool-call normalization
- `gate.py`: `Gate` with `default="deny"|"allow"`, `check`/`execute` split, `run`/`run_all`, verdict enum
- Audit events for every verdict via surviving `Meter` (JSON/CSV export)
- `toolwall report` CLI
- New test suite: intake shapes, all gate verdict paths, schema, meter, CLI

### Removed
- TOAP DSL: parser, encoder, compare, few-shot prompts, LangChain/CrewAI adapters
- `toap-bench` harness (superseded; failure-scenario suite lands next cycle)
- All compression claims

### Carried over
- `schema.py` (+ `schema_from_signature`), `meter.py`, fail-closed proxy control flow, MIT license

### Added (phase0-completion cycle, same day)
- `policy.py`: value constraints (`in_range`, `one_of`, `matches`, `ends_with`, `starts_with`, `max_len`, `not_empty`), cross-arg rules, `require_approval`; raising rules fail closed
- Budget caps on the gate: `max_calls`, `max_calls_per_tool`, `max_usd` (meter-derived)
- Approval flow: `NEEDS_APPROVAL` verdict, optional handler on `run`/`run_all`, fail-closed without one
- `shield.py` (D-019): secret patterns (AWS, Google, GitHub, Stripe, Slack, OpenAI, JWT, PEM, credential assignments) + entropy heuristic; modes redact/block/warn; in-memory placeholder vault; findings and audit events never carry values
- Meter D-016: `extract_usage()` pulls exact token counts from OpenAI/Anthropic/Gemini responses; heuristic counts flagged `estimated=true`; summary reports estimated-event count
- `gate-suite/`: 24 attack cases across 9 classes + 10 clean cases; G1 result: 24/24 blocked, 0 false blocks, p95 0.07 ms (`gate-suite/results/REPORT.md`)
- Test suite grown to 70 tests

### Added (phase1-dryrun cycle, same day)
- Dry-run mode: `Gate(dry_run=True)` simulates ALLOW calls (budget still enforced), never executes; `GateResult.dry_run` flag
- `gate.report()`: verdict counts, per-tool table, blocked reasons, secret findings by kind
- `suggest.py`: `suggest_policies(gate)` turns observed calls into a reviewable draft of `register()` calls (schema required/types, `in_range` from observed numerics, `one_of` from small string sets)
- `examples/dangerous_agent_demo.py`: same six off-the-rails tool calls replayed ungated (table wiped, secret emailed, unauthorized deploy) vs gated (1 allowed, 5 blocked, world untouched)
- Test suite grown to 76 tests

### Added (phase1-dryrun cycle, same day)
- Dry-run mode: `Gate(dry_run=True)` simulates execution for ALLOW verdicts; blocks still block; `GateResult.dry_run` marks simulated steps
- `Gate.history` + `Gate.report()`: verdict counts, per-tool breakdown, blocked reasons, secret-finding kinds (value-free)
- `suggest.py` `suggest_policies()`: turns observed calls into a reviewable draft of `register()` + `ToolSchema` + `Policy` (ranges/enums from observed values; every line flagged for human review)
- `examples/dangerous_agent_demo.py`: an off-the-rails agent replayed with vs without the gate (defensive demonstration; no real side effects)
- Tests grown to 76

### Added (phase1-mcp cycle, same day)
- `mcp_guard.py`: `MCPGuard` puts a Gate in front of any MCP server; only ALLOW calls forward, blocks/held return an MCP-style tool error (`to_mcp_error`). Decision core is framework-free and fully unit-tested without an MCP install
- Shield redaction is applied to forwarded args (server never sees the secret)
- `mcp` optional extra (`pip install toolwall[mcp]`); core stays stdlib-only
- `examples/mcp_guard_demo.py`
- D-020: neutral vocabulary in defensive fixtures (avoids content-classifier false flags); suite classes renamed, coverage unchanged
- Tests grown to 85

### Added (phase1-release cycle, same day)
- Verified the package builds (`python -m build`), passes `twine check`, and installs
  clean into a fresh venv with zero required deps (only `mcp`/`dev` extras)
- `toolwall/RELEASING.md`: manual, owner-run publish steps (Test PyPI first)
- `mcp>=1.0.0` optional extra confirmed in built metadata

### Pending (next cycles, per plan.md)
- MCP stdio transport wiring (lands with first real pilot)
- PyPI publish (manual step, owner runs with their own token)
- Approval CLI UX

## [0.1.0-alpha] - 2026-08-19 (TOAP, archived)

See `toap-v0.1-archive` branch. SDK: DSL parser, proxy middleware, CLI, prompt builder,
LangChain/CrewAI adapters, benchmark harness. Gemini-validated format compliance 100%,
net token savings ~5-6% — later re-measured negative vs fair baselines. Archived.
