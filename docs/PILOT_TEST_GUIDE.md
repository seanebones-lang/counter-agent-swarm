# Voluntary developer-preview test

Created by NextEleven. This is a small, local evaluation using fictional runs
and inert data, not a production security deployment or an unpaid work assignment.
Plan for 30–45 minutes. Stop whenever something is unclear or unexpected.

## Choose the actual available scope

**Public component test:** Packaged CI has tested Python 3.12 on Ubuntu and
Python 3.13 on macOS/Linux.
An external tester also reported a passing Python 3.12.3 run on Ubuntu 24.04
under WSL2, as root. That does not validate ordinary-user permissions or native
Windows support. Native Windows is unsupported by the Unix worker and
file-permission code. No account, model credential, purchase, Mothership
source or DeadBolt executable is needed for this component suite.

From an authorized copy of the glue repository:

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python scripts/test_glue_only.py
```

On Ubuntu 24.04, `python3.12` is another interpreter permitted by the package's
Python >=3.11 requirement. A missing `ensurepip` error usually requires the
matching Ubuntu `python3.12-venv` package through your normal authorized admin
process. Run project installation and tests as an ordinary user, without sudo.
Use a fresh extraction in your Linux home; GNU tar's `--no-same-owner` avoids
restoring the macOS archive's owner metadata. Do not broadly change ownership
of existing directories. See the focused [ordinary-user WSL follow-up](UNPRIVILEGED_WSL_FOLLOWUP.md)
and [glossary](GLOSSARY.md).

To run the same component suite and collect return files in one step, use
`.venv/bin/python scripts/collect_component_results.py --out ./pankaj-results`
instead of the last command. The output directory must be new. It writes
`results.json`, `test-output.txt` and a `feedback.md` template; it uploads nothing.
Fill in the feedback, inspect/redact the files, then return those three files by
reply email. If you redact anything, mention which file changed: the included
log hash describes the original locally collected, path-redacted log, while we
will separately hash the actual version received. A `needs-review` result is
useful feedback and must not be changed to make the run appear successful.

Witness recording is optional and handled on NextEleven's side after return.
With the tester's agreement we can retain the report and received-file hashes
in a private local record, attribute claims to their source, and record later
corrections separately. This provides provenance of the received report; it
does not verify who operated the computer, whether the test was honest, or
whether the software is secure. No public acknowledgement is assumed.

Use a new environment; the script selects the public component tests explicitly.
It tests deterministic indicators, bounded proxy behavior, gate refusals, model
adapter fixtures, queue capacity/archival, supervisor fixtures, and intel/sandbox
adapter fixtures. Passing it does **not** test the real Mothership or DeadBolt loop.
No actual exploit is executed. No active WAF rules are installed.

**Full private native integration:** Only available after NextEleven separately
provides an authorized Mothership runtime and agrees on the tester's OS/CPU.
Do not install an unrelated public package named Mothership. A Python wheel
normally contains readable implementation; private runtime access is a separate
license decision and is not implied by Apache-2.0 on this glue.

The full test uses reviewed Mothership 0.3.0 and DeadBolt 2.0.0:

```sh
.venv/bin/python -m pip install /absolute/path/to/authorized-mothership.whl
.venv/bin/python -m pytest -q
.venv/bin/python scripts/acceptance.py --deadbolt /absolute/path/to/reviewed/deadbolt --out acceptance-local.json
```

The regular suite intentionally skips its duplicate native-acceptance test unless
opted in. Run the acceptance command above separately. Expected receipt: `status`
is `passed`, four scenarios, `processes_stopped` and `disposable_stores_removed`
are true, and `model_operated` is false. The three control scenarios should show
healthy forwarding, blocked inert indicators, pending approval before any native
effect, approved fixed-target effects, no duplicate event on replay, and denied
subsequent forwarding without an increase in the upstream counter. The fourth
scenario checks missing credentials, a broken disposable lease store and a
stopped gate. Acceptance provisions fictional state on loopback and removes it.

## Feedback to send back

Share only the information relevant to this test. Redact personal paths, machine
identifiers and any unrelated logs before sending. Never send a `.env`, API key,
account token, real customer request, application database or raw exploit sample.

1. OS/version, CPU architecture, Python version, and selected scope.
2. Did the exact installation commands work? If not, the first failing command
   and a short redacted error. Do not work around it by changing system security.
3. Test summary and, for the full scope, the generated acceptance receipt.
4. Which instruction or distinction was unclear? Could you tell what is a real
   native effect, a mocked fixture, an approval and an unvalidated claim?
5. Any unexpected network request, prompt, remaining process or state directory?
6. The most useful improvement before another developer tries this.

If native acceptance fails, preserve the redacted output and stop. Do not point
it at an existing application or database, approve unfamiliar actions, replace
keys to evade an unknown outcome, or try real attacks to see whether it works.

## Cleanup and honest limits

After stopping the test, delete only the disposable `.venv` and the test copy you
created when no longer needed. Keep the redacted result you intend to share.
Acceptance itself verifies teardown of its temporary native services and stores;
its success is not a proof of recovery for any real system.

This preview has no validated production/Railway deployment, sustained attack-load
result, independent adversarial assessment, real sandbox detonation or live
frontier-analyst judgment result. The model suggests actions; native approval
remains required. DeadBolt stops the next cooperative admission and cannot undo
already running code. The protected origin must not be directly reachable.
