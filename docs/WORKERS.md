# One-shot operator workers

The worker commands are adapters around existing components. They do not introduce
another orchestration brain, scheduler, model agent, approval system, or rule
activation path. Use the existing Mothership installation and a suitably scoped
agent identity; never reuse an owner/admin credential for routine feed ingestion.

Run either installed source entrypoint:

```sh
python -m counter_swarm.worker_commands intel --config /absolute/private/intel.json
python -m counter_swarm.worker_commands intel --config /absolute/private/intel.json --reconcile
python -m counter_swarm.worker_commands sandbox --config /absolute/private/sandbox.json --payload /absolute/private/payload.bin
```

`intel_main()` and `sandbox_main()` can also be exposed as packaging console
entrypoints. Both call `main(argv)` with a fixed subcommand. Exit codes: 0 means a
verified memory receipt or newly created proposal, 2 means reconciliation/duplicate
proposal requires attention, and 1 means configuration or execution failed. Errors
are generic bounded JSON; exception strings, credentials and captured payloads are
not printed. There are no automatic network or subprocess retries within a run.

## Fixed private configuration

Create configuration and credential files with owner-only permissions (0600),
and existing state/proposal directories with owner-only permissions (0700).
Configuration must use an absolute path; symlink config files and directories are
rejected. Keep state outside Git and persistent across worker restarts. The
configured Mothership endpoint is HTTPS, or explicit literal HTTP loopback; URLs
cannot contain credentials, query strings or arbitrary paths. No feed URL can be
configured: the intel module uses only its fixed official CISA KEV endpoint.

Example **intel.json** (fictional identifiers; no secret in the JSON):

```json
{
  "system_id": "protected-example",
  "mothership_origin": "http://127.0.0.1:8787",
  "api_key_file": "/absolute/private/mothership-agent.key",
  "state_directory": "/absolute/private/intel-state",
  "cve_ids": ["CVE-2026-12345"],
  "namespace": "swarm.intel"
}
```

Select real CVEs relevant to the operator's protected inventory. The fictional
example CVE must be replaced; absent selected CVEs cause a failure, not invented
advisories. At most 50 records are selected, with a 64 KiB serialized worker-record
budget. A selected record is evidence for review, not a finding that an application
is affected. The credential must authenticate an agent permitted by Mothership's
native policy to call `memory.put` in the intended namespace. The adapter does not
grant scopes or approvals. It uses the existing SDK with zero retries and no
automatic approval waiting; it disables inherited transport proxy configuration.

The poller persists the exact `memory.put` input, protected-system/origin binding,
and deterministic idempotency key in `intel.pending.json` **before** the SDK call.
Its separate owner-only `intel.pending.status.json` marker records the outcome
classification and original approval ID when supplied. Pending input/key remain
unchanged. Any unresolved outcome returns `pending_reconciliation`; **subsequent
ordinary or scheduled invocations halt without an SDK call or another feed fetch**.

The operator may explicitly pass `--reconcile` in two cases. With no pending job,
the flag returns `no_pending_reconciliation` without fetching or creating work.
For an original
`APPROVAL_PENDING`, it calls native `client.wait_for_approval(original_id, timeout=1)`
and never resubmits `memory.put`. A wait timeout preserves that same approval ID.
For SDK transport/envelope uncertainty (`OUTCOME_UNKNOWN` with SDK status 0), the
flag invokes the native receipt/idempotency path with the exact original input/key
and zero retries. If an approval ID is already saved, it always uses the approval
wait path rather than resubmitting an action. A **native** `OUTCOME_UNKNOWN`, an
unverified receipt, a crash with an unclassified/dispatching marker, and other
blocked errors stay held even with `--reconcile`: inspect native evidence and
resolve through the operator's existing Mothership workflow. An unknown native
outcome does not authorize reexecution.

Changing bindings or editing the input without its matching digest fails. Do not
delete pending records or generate a new key to get past uncertainty. Verified
receipts are recorded as bounded hashes, and only then is pending state removed.
A local exclusive file lock prevents concurrent invocations sharing one directory.

This is a minimal durable handoff, not a new incident database. Native Mothership
idempotency retention, persistence and receipt recovery must be configured for the
operator's intended scheduling interval. If the retained native receipt is gone,
the same `memory.put` may create another version of the same content-addressed
record; it cannot activate a WAF rule or authorize a defensive action.

Example **sandbox.json**:

```json
{
  "image": "registry.example/reviewed-analyzer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_daemon_id": "replace-with-dedicated-host-daemon-id",
  "dedicated_host_confirmed": true,
  "docker_host": "unix:///var/run/docker.sock",
  "wall_seconds": 15,
  "payload_limit": 65536,
  "proposal_directory": "/absolute/private/proposals"
}
```

The digest above is a **placeholder**, not a supplied or runnable image. The
runtime, pinned reviewed image and dedicated host are not supplied or validated by
this project. Ordinary Railway containers/shared Docker do not satisfy this
boundary. See [SANDBOX.md](SANDBOX.md) before enabling anything. There is no remote
worker transport; run this adapter on the separately validated isolated host.

The sandbox worker reads a private regular payload file, or at most
`payload_limit + 1` bytes of stdin if `--payload -` is used, then delegates to the
existing constrained `SandboxWorker`. Captures must be sanitized by the operator
before submission; no claims of automatic secret removal are made. No commands,
image overrides or execution flags come from payload contents. The only persisted
output is the immutable, human-review-required JSON proposal. It is never loaded
into active detection. A duplicate proposal is left untouched and returns exit 2.

## Scheduling and validation limits

Invoke a one-shot intel job from an existing approved scheduler/Mothership workflow
when desired. This module installs no cron entry, timer, background service or
Railway job and makes no unsolicited live requests on import. No honeypot endpoint
or arbitrary feed importer is added.

Tests use fictional catalogs, fake native SDK clients, a fake sandbox worker, and
temporary private directories. They verify stable keys, persistence across an
uncertain result, zero automatic dispatch/fetch while pending, explicit transport
reconciliation, waiting on the original approval without resubmission, native
unknown outcomes held even with the flag, binding-change refusal,
unverified-receipt refusal, secret-free error output and exclusive proposal
behavior. No public feed/API request, Docker execution, credential use, actual
Mothership memory write or production scheduling occurred in this worker test.
