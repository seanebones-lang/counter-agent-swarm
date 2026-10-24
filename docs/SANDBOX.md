# Sandbox and public intelligence boundary

These adapters are deterministic glue. They make no AI calls and cannot activate
detection rules, change a WAF, grant approvals, or invoke DeadBolt. Analysis output
and public feed content remain untrusted data, including any embedded instructions.

## Detonation is disabled until a dedicated host is validated

Ordinary Docker, a shared developer daemon, and ordinary Railway containers are
**not adequate isolation for hostile payload execution**. Do not mount a Docker
socket into a Railway service. Run `SandboxWorker` only on a separately provisioned,
operator-controlled isolated host with a pinned daemon ID and installed gVisor
`runsc`. Railway can later enqueue a bounded job to that host over an authenticated
channel; that channel, queue, per-system authentication, rate limits, VM hardening,
and production image are not implemented by this adapter.

`SandboxConfig` requires an explicit dedicated-host acknowledgement, exact daemon
ID, and image reference ending in `@sha256:<64 hex>`. There is no default runnable
image. Pull and review an image separately; this worker uses `--pull never`.
`docker info` must confirm the daemon ID and registered `runsc` runtime. This is a
prerequisite check, not cryptographic attestation of gVisor or a substitute for host
hardening. Pin/review the runtime binary and container image in deployment controls.

The fixed image contract is `/counter-swarm/analyze`: read at most 64 KiB of raw
payload bytes on standard input, run only the intended bounded parser/analyzer,
and emit one JSON object on standard output:

```json
{"summary":"Observed parser result","findings":["Bounded factual observation"],"candidate_literals":["literal candidate"]}
```

The caller cannot supply a command, flags, image, path, mount, or environment.
Containers run as UID/GID 65534 with a read-only root, no network, no IPC namespace
sharing, all capabilities dropped, no new privileges, no volumes, bounded CPU,
128 MiB memory/swap ceiling, 64 PIDs, descriptor/file-size limits, no persistent
Docker logs, and a maximum 30-second wall time. Images declaring volumes are
rejected. Standard output is capped at 64 KiB and standard error at 8 KiB. A
container is force-removed after success, timeout, malformed output, or output
overflow; failure to verify cleanup is an error requiring host isolation. Resource
exhaustion and runtime/kernel vulnerabilities still require external containment,
monitoring and an independent reaper. This is not a generic arbitrary-code service.

The worker emits the payload hash and pinned image with its observation. Literal
rule proposals are content-addressed JSON created exclusively with owner-read-only
permissions; they are never loaded by the detector. This makes accidental overwrite
fail, not a tamperproof evidence store (the file owner can still change permissions).
A separate human-reviewed, versioned activation process must assess false positives,
scope, expiry, rollback, and immutable evidence before enabling any rule. No model
output or sandbox output can bypass that process.

## Intelligence poller

`poll_kev()` performs one bounded fetch from CISA's fixed official HTTPS KEV JSON
endpoint. An operator scheduler can call it periodically; it is not in the request
hot path. It follows no redirects, uses no environment proxies or credentials,
rejects encoded responses, enforces connection/read/total timeouts and an 8 MiB
stream limit, and validates known catalog/advisory fields, CVE/CWE IDs, dates,
duplicate keys, counts and text bounds. Schema changes fail visibly and preserve
previous operator-approved policy; feed failure does not authorize traffic or
erase existing blocks. The feed does not supply exploit execution or WAF rules.

`memory_handoff(catalog, cve_ids)` produces up to 50 selected advisory records with
source/hash and explicit `instruction_authority: false`. It is an adapter payload,
not a claim that a native Mothership memory endpoint has been called. Treat the
record as evidence for response-agent review and patch prioritization. An advisory
does not establish that a protected system uses an affected version or was attacked.

## Validation status

Unit tests use fictional payloads, a fake Docker process adapter, HTTP mock
transport, and inert Python children for subprocess output/time budgets. They test
refusal of unconfirmed/shared hosts, missing runtime, image volumes, constrained
command construction, cleanup, observation/proposal limits, feed schema and fetch
boundaries. No Docker daemon or sandbox image was started, no suspicious payload
was executed, and no public feed was contacted during these tests. Actual gVisor
isolation, hostile parser behavior, remote transport, scheduling, live KEV
availability/schema, and Railway-to-dedicated-host integration remain unvalidated.
