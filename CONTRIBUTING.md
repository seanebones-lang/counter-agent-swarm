# Contributing to Counter-Agent Swarm

Thanks for helping NextEleven build a reproducible defensive developer preview.
This is voluntary, unpaid open-source participation, with no employment or
internship attached. Choose the time you want to contribute. Tests, documentation,
reproductions and careful review are useful contributions alongside code.

The new glue is Apache-2.0. Mothership remains a separate proprietary dependency;
do not copy its source, credentials or artifacts into this repository. DeadBolt
also remains external. The public component suite needs neither engine.

## First test

Follow the [README quickstart](README.md#start-here-public-component-preview) and
[pilot guide](docs/PILOT_TEST_GUIDE.md). Run the original source first. The
collector produces a test report, log and feedback template locally and uploads
nothing. A failing test or installation step is useful evidence; retain it before
trying a change. Native Windows is unsupported. See the pilot guide for tested
Python environments, Ubuntu prerequisites and ordinary-user WSL instructions.

For a public bug/test report include OS/version, CPU, Python, revision, first
failing command, expected/actual behavior and a minimal inert reproduction.
Inspect and redact output before posting. Do not upload `.env` files, keys,
tokens, private machine paths, customer requests or application databases.
Returned reports and hashes are self-reported evidence, not certified results.
Private feedback can be sent to **hello@nexteleven.dev**.

## Security reports

Read [SECURITY.md](SECURITY.md). Send potential vulnerabilities privately to
**hello@nexteleven.dev** or use GitHub's private vulnerability-reporting feature
if enabled. Do not disclose a working exploit or private payload in a public
issue. Use only your own authorized disposable environments and inert fixtures.

## Changes and validation

Keep changes focused and explain the problem, behavior change and validation.
Add a regression that tests a meaningful failure boundary where appropriate.
Run `python scripts/test_glue_only.py` for the public suite. Full pytest/native
acceptance needs authorized external engines and is a distinct validation scope.

Preserve deterministic detection/enforcement, fixed targets, native approvals,
original action keys and held unknown outcomes. Treat request, feed, model and
sandbox content as untrusted data. Avoid new ambient access, automatic active-rule
promotion or paid provider calls in tests. Do not fork or embed either engine.

Submit a pull request against `main`, describing what actually ran and what
remains untested. Public CI exercises packaged components; it does not certify
production protection, live sandbox isolation or real model judgment. Please
retain Apache-2.0 copyright/license notices. Submissions are intended under the
repository's existing Apache-2.0 contribution terms; no extra CLA is required.

## Credit and privacy

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for agreed public acknowledgements.

We are happy to acknowledge people who help as official project contributors
and testers, with their agreement. Tell us the name or GitHub handle you want
used and whether you want a public acknowledgement. Private email/feedback is
not published by default. Public GitHub contributions already display the
account and commit metadata you choose to submit.

Optional Witness recording can retain returned reports and file hashes in a
private local provenance record. It requires the tester's agreement and does
not independently prove execution, identity or the truth of a report. No
automatic upload or Witness submission is part of the test collector.

## Using the open-source work

You are welcome to use this public glue in learning, portfolio projects and
commercial work under its existing Apache-2.0 license. When distributing it or
derivatives, follow that license, including the applicable license, copyright,
NOTICE and modification notices. There is no additional obligation to test for
NextEleven in exchange for using the software.

Other public NextEleven repositories and external dependencies have their own
licenses; check each one. This invitation does not grant access to the private
Mothership runtime or permission to imply NextEleven endorses a derivative.
