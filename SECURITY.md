# Security policy

toolwall sits between an AI agent and its tools, so a hole in it can let a call
run that should not. Please report those privately, so a fix can ship before
the details are public.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| below 0.4 | No, please upgrade |

## How to report

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/Dev-Saif-Ops/toolwall/security/advisories/new)
(the repository's Security tab). Only you and the maintainer can see the report.

If you cannot use GitHub, email **devsaifops@gmail.com** with the subject line
`toolwall security`.

Please do not open a public issue, discussion or pull request for anything in
the "Report privately" list below.

A useful report has:

- the toolwall version (`python -c "import toolwall; print(toolwall.__version__)"`)
  and Python version
- the tool registrations (schema, policy, shield mode) and the call or return
  value that gets through
- what the gate did and what you expected it to do
- a minimal script that reproduces it, if you have one. Half-formed is fine.

## What to report privately

Anything where the documented configuration does not hold, for example:

- a call the documented schema or policy should block gets `ALLOW`, or the tool
  runs without an `ALLOW`
- a secret pattern toolwall claims to detect reaches the model, the tool, a
  block reason or the audit log
- the gate fails open: an exception, hang or malformed input leads to execution
  instead of a verdict
- a result runs twice, runs for a different tool or with different arguments
  than were checked, or a held or denied result runs
- `MCPGuard` forwards something the same `Gate` would not run

## What can be a public issue

These carry no risk to anyone, and an issue is faster:

- false blocks (a legitimate call or output that gets blocked or withheld)
- the gate raising an exception where nothing executes
- new attack ideas for the published suite, docs problems, feature requests

## Known limitations (not vulnerabilities)

These are documented and out of scope as reports, though ideas to close them
are welcome as issues:

- secrets without recognizable structure (plain passwords) or that are encoded
  (hex, URL-encoding, homoglyphs). Detection is pattern and entropy based.
- tool outputs that are not plain data are withheld, not scanned field by field
- attacks spread across several calls that are each allowed on their own
  (sequence and data-flow rules are on the roadmap)
- mistakes in policies you write yourself, such as using `ends_with` for email
  recipients instead of `email_domain`
- the verdict covers the arguments, not the state of the world: a resource
  swapped after the check is outside what the gate can see

## What happens next

toolwall has one maintainer, so these are targets, not guarantees:

- acknowledgement within 3 days
- an assessment (confirmed, not a vulnerability, or more information needed)
  within 7 days
- for confirmed issues, a fix and a release within 30 days, sooner for anything
  that is easy to exploit

You will be kept informed along the way. Once a fix is released, the advisory
is published, and the finding is credited to you in the
[changelog](CHANGELOG.md) and on the site's hall of fame, unless you prefer to
stay anonymous. There is no paid bug bounty.

## Good-faith research

Testing toolwall on your own machine, against your own agents and tools, is
welcome and needs no permission. Please do not test against systems or data
that are not yours.
