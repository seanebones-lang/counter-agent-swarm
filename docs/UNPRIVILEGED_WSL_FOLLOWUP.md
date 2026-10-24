# Voluntary ordinary-user WSL follow-up

Pankaj's first report was detailed and useful. It reported 69 component tests
passing, but its root-user run could not exercise ordinary-user permissions.
This small follow-up checks that gap. Allow 15–20 minutes; there is no deadline,
obligation or employment commitment. A blocked setup is a useful result.

## Scope and prerequisites

Use the **original unchanged 0.1.0 source archive** we sent, not a new download
with a different checksum. This repeats the same public component suite. It
does not need Mothership, DeadBolt, model keys, real traffic or paid services.
It does not run real exploits or establish native Windows support.

Use an **existing ordinary Ubuntu/WSL user** and a fresh directory in its Linux
home, not `/mnt/c` or the old root-owned extraction. Check `id -u` first. If it
prints `0`, stop and report that an ordinary-user environment is unavailable.
Do not create users or change system security just to complete this test.

If Python 3.12 reports missing `ensurepip`, Ubuntu may need its matching
`python3.12-venv` package through your normal authorized administrator process.
Do not run the project, collector or pip installation with sudo. If that
prerequisite cannot be supplied normally, return the error instead.

## Verify, extract and run

Place the original archive in your Linux home. Adjust only the archive path if
its filename differs. Run these first:

```sh
id -u
python3.12 --version
sha256sum "$HOME/n11_counter_agent_swarm-0.1.0.tar.gz"
```

**Stop on a checksum mismatch.** The expected archive SHA-256 is:

```text
3a521c93a821c9cd6b6dbc19cb11995530938abd86d42872bb62fcd6db9e702a
```

After confirming a nonzero UID and matching checksum:

```sh
umask 077
test_dir=$(mktemp -d "$HOME/swarm-followup.XXXXXX")
tar --no-same-owner -xzf "$HOME/n11_counter_agent_swarm-0.1.0.tar.gz" -C "$test_dir"
cd "$test_dir/n11_counter_agent_swarm-0.1.0"
python3.12 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python scripts/collect_component_results.py --out ./unprivileged-results
```

GNU tar's `--no-same-owner` keeps extracted files owned by your current user
rather than trying to restore macOS archive ownership. Do not recursively chown
an existing workspace. Keep the fresh extraction for diagnosis if a step fails.

Expected: 69 passed, collector exit code 0. The unchanged runtime source
fingerprint should be:

```text
0de3e51286a8dece1b1bfc0aac41bc4cd701970abcd36ff42278982181715887
```

## Return the result

Inspect and redact `results.json`, `test-output.txt` and your completed
`feedback.md` before replying with those three files. Note any redaction since
the collector's log hash describes its original output. Tell us:

1. Ubuntu/WSL, Python and architecture versions, and whether UID was nonzero.
2. Whether extraction, installation and result creation worked without sudo.
3. The first failing command and short redacted error, if any. Do not edit tests
   or source to make the run pass.
4. Whether the [glossary](GLOSSARY.md) clarifies kill, deny, revoke and
   next-admission-only enforcement.

Never include keys, `.env` files, customer data or unrelated machine logs.
There is no automatic upload. Your first report remains valuable even if you
choose not to repeat anything. A native-engine exercise would be a separate
invitation after we verify suitable artifacts and agree on its scope.
