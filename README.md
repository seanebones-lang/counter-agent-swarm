# Counter-Agent Swarm

[![Public component preview](https://github.com/seanebones-lang/counter-agent-swarm/actions/workflows/public-components.yml/badge.svg)](https://github.com/seanebones-lang/counter-agent-swarm/actions/workflows/public-components.yml)

Small defensive glue connecting deterministic request screening, an **external
unmodified Mothership**, and **external DeadBolt 2.0.0**. One protected application
per instance. No new dashboard. This repository is Apache-2.0; the dependencies
retain their own licenses. Mothership is currently proprietary and must be
obtained separately with permission. An open-source glue layer does not make
the entire dependency stack open source.

**Status: local synthetic integration proof, not production protection.** Real
Mothership → stdio MCP → native DeadBolt kill/deny/revoke acceptance passes.
The analyst in that proof is a deterministic test fixture. Live frontier-model
analysis, hostile-payload detonation, production deployment, performance
under attack and independent adversarial evaluation remain unvalidated. No
protected real application has been changed or deployed by this project.

Created by **NextEleven**. The public component suite can be evaluated without
Mothership or a model credential; full native integration needs separately
authorized engine access. See the [pilot test guide](docs/PILOT_TEST_GUIDE.md),
[glossary](docs/GLOSSARY.md) and [contributors and testers](CONTRIBUTORS.md).

## Start here: public component preview

**Source:** https://github.com/seanebones-lang/counter-agent-swarm

Volunteer testers and contributors are welcome. Participation is unpaid, with
public contributor/tester credit by agreement. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for scope, results, private security reporting and attribution.

Packaged CI has tested Python 3.13 on macOS and Linux. An external tester also
reported Python 3.12.3 passing on Ubuntu 24.04/WSL2 as root; ordinary-user WSL
verification remains a separate follow-up. See the pilot guide for Ubuntu venv
prerequisites. Use a fresh ordinary-user environment; native Windows is not
supported by the Unix worker/permission code.
No model key, private engine, cloud account or production application is needed:

```sh
git clone https://github.com/seanebones-lang/counter-agent-swarm.git
cd counter-agent-swarm
python3.13 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python scripts/collect_component_results.py --out ./component-results
```

The collector runs the explicit public subset, currently **76 tests**, and writes
`results.json`, `test-output.txt` and `feedback.md`. It uploads nothing. Inspect and
redact the files before sharing. Use a new output directory for another run.
Do not run the entire pytest directory without the separately authorized native
dependencies: it contains Mothership-specific tests. Public component results
do not establish actual native integration, live model judgment or deployment.

Source distributions include tests, scripts, examples and instructions. The
smaller wheel contains the glue runtime only. Public CI builds and installs the
source distribution outside the checkout before running the component suite.
The first public run passed all 69 component tests on Ubuntu and macOS with
Python 3.13: [packaged test results](https://github.com/seanebones-lang/counter-agent-swarm/actions/runs/40060498003).
This does not validate Linux native-engine deployment or sandbox isolation.

## Architecture

For an operator-hosted real-engine pilot that keeps Mothership private, see the
[Linux native lab guide](docs/LINUX_NATIVE_LAB.md). Its public tester kit contains
only a client and instructions; the private runtime image stays with the operator.
Live analyst judgment and hostile-payload detonation remain separate scopes.

```text
request → bounded deterministic proxy → fresh DeadBolt admission → fixed private origin
              │ suspicious: 403                │ unavailable/denied: 503
              └→ authenticated metadata ingress → bounded durable transport queue
                                                     │ off path
                                     existing Mothership memory + swarm.analyze
                                                     │ native owner approval
                                            swarm.kill / deny / revoke
                                                     │ fixed-target stdio MCP
                                           external DeadBolt CLI / store

official CISA KEV → reviewed inventory selection → Mothership memory (untrusted)
separate isolated sandbox host → immutable rule proposals → human review
```

Detection and enforcement contain **no AI calls**. A suspicious request is denied
before incident delivery or analysis. Benign forwarding requires a fresh exact
DeadBolt allow; missing credentials, invalid replies, unavailable services and
damaged lease stores cannot authorize forwarding. The protected origin must be
private: direct origin access bypasses a cooperative proxy.

The model can recommend an action, not approve it. Every new model analysis and
system-wide control action requires Mothership's native approval. Analysis runs
inside the glue-owned `swarm.analyze` tool registered into an unmodified Mothership
application bootstrap. There is no invented Mothership plugin/configuration API.
The existing dispatcher supplies scope checks, idempotency, approvals and evidence.

## Optional native proof with separately authorized dependencies

For component testing without the private runtime, install `.[test]` into a new
environment and run `python scripts/test_glue_only.py`. This deliberately excludes
native integration rather than silently substituting an imitation engine.

Prerequisites: Python 3.12 or 3.13 in the recorded tested environments, a separately installed reviewed Mothership
0.3.0, native DeadBolt 2.0.0, and the dependencies in `pyproject.toml`. Install
Mothership from your authorized source/artifact; do not install an unrelated
similarly named public package.

```sh
python -m venv .venv
.venv/bin/python -m pip install /absolute/path/to/reviewed-mothership.whl
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/python scripts/acceptance.py --deadbolt /absolute/path/to/deadbolt --out docs/acceptance.json
```

The harness creates disposable private stores and identities, starts real services
on loopback, and checks an independent upstream request counter. It verifies:

- Healthy request: 200 and one upstream request.
- Inert exploit-shaped indicator: 403 and no additional upstream request.
- Incident recorded in native Mothership memory; action waits for approval.
- Owner fixture approves; actual external stdio MCP calls actual DeadBolt.
- Kill, clip-forwarding deny and admission-credential revocation independently
  block the next benign request with 503; the upstream count remains unchanged.
- Same-key receipt replay creates no second native control event.
- A separate controller still reads evidence after the target is killed.
- Missing credentials, a broken disposable lease table and a stopped gate deny.
- Temporary services and stores are cleaned up.

See the retained [acceptance receipt](docs/acceptance.json). This is protocol
automation by the development team, not an independent or model-operated test.
The opt-in native pytest also runs when `COUNTER_SWARM_TEST_DEADBOLT` is set.

## Tools and trust boundaries

| Mothership tool | External MCP tool | Actual effect |
| --- | --- | --- |
| `swarm.kill` | `deadbolt_kill` | Kill the fixed target run; deny subsequent admissions |
| `swarm.deny` | `deadbolt_deny` | Clip the fixed `web.forward` tool |
| `swarm.revoke` | `deadbolt_revoke` | Revoke the fixed admission credential, not every credential |
| `swarm.evidence` | `deadbolt_evidence` | Read bounded native evidence for the fixed target |
| `swarm.analyze` | none | Approved bounded model advice; no model tool invocation |

The MCP facade accepts a reason and incident ID, never a target, URL, shell command,
database path or credential. The trusted owner-only binding selects those.
No provisioning, renewal, resume or approval tools are exposed through this facade.
MCP uses local stdio, not an unauthenticated network listener.

Use separate DeadBolt runs for the controller and protected target. The controller's
native allowlist should contain only `swarm.kill,swarm.deny,swarm.revoke,swarm.evidence,
swarm.analyze,memory.put,memory.get,memory.checkpoint_save` as required. Mark those
as offline tools when using destination policies, because these dedicated adapters
own their fixed endpoints. Do not grant generic `http.request` to the controller.
Owner routes and `approvals.wait` remain subject to native Mothership semantics.

DeadBolt kill is **next-admission enforcement**, not termination of in-flight HTTP
requests, OS processes or malicious code already executing in an application.
A same-user/root process able to edit credentials, policies, binaries or stores is
outside this cooperative enforcement boundary. Events are local records, not
independent evidence custody.

## Per-system runtime

Copy the example JSON files into a private directory outside Git. Set their real
fixed identifiers and origins, permissions 0600 for files and 0700 for directories.
Provision both native runs/policies/credentials first using reviewed DeadBolt tools.
Create the Mothership controller through its existing owner API, using
[`examples/mothership-agent.json`](examples/mothership-agent.json). The native
acceptance script is an executable provisioning reference for disposable identities.

Set the paths and mandatory native gate configuration shown in `.env.example`.
The processes can be started individually:

```sh
python -m uvicorn counter_swarm.mothership_ext:create_app --factory --host 127.0.0.1 --port 9783 --no-access-log
python -m uvicorn counter_swarm.runtime:configured_ingress --factory --host 127.0.0.1 --port 9784 --no-access-log
python -m uvicorn counter_swarm.runtime:configured_proxy --factory --host 127.0.0.1 --port 8080 --no-access-log
counter-swarm work
counter-swarm status
counter-swarm resume --event-id ORIGINAL_INCIDENT_ID
```

Start DeadBolt's authenticated loopback sidecar separately against the same trusted
database/events binding. `work` handles one queued incident. Default behavior saves
the finding and escalates in Mothership, with no model request or system-wide action.
An authenticated metadata ingress queues at most 2,048 content-addressed incidents;
duplicate IDs do not enqueue twice. Queue-full/delivery failures leave suspicious
requests blocked and emit a bounded delivery-failure log. Archive completed incidents
under an operator-approved retention policy; this prototype does not silently evict
pending or uncertain work.

Use the explicit operator command `counter-swarm archive-completed --destination
/absolute/private/archives/new.jsonl` to durably export completed records and
reclaim their slots. See [queue operations](docs/QUEUE_OPERATIONS.md) for failure
reconciliation and the public listener's resource bounds.

Claims become held before remote work. A crash or unknown outcome requires
operator reconciliation. `resume` only waits on the saved original approval; it
cannot approve it, silently requeue a held incident or generate a new action key.
Mothership's stored results are the authoritative execution receipts.

## Optional frontier analysis

Live calls default to **zero** even when a key exists. To enable an approved trial,
configure `COUNTER_SWARM_MODEL` with an available reviewed model,
`COUNTER_SWARM_MODEL_BUDGET_FILE` with a persistent private absolute SQLite path,
`COUNTER_SWARM_MAX_MODEL_CALLS` with an explicitly approved allowance (1–100), and
set `live_analysis: true` in the runtime JSON. Load `OPENAI_API_KEY` through a private
runtime secret mechanism. No secret is included in examples, images or receipts.

The initial provider adapter uses OpenAI's Responses API with strict structured
output, `store: false`, 600 output tokens maximum, a total request deadline, and
at most 4 KiB of projected input. It sends only opaque fingerprint/incident IDs,
known detector rule IDs and severity/revision. It sends no raw body, URL, request
header or client address, and gives the model no tools. Other providers implement
the small `Analyst` protocol; detector, gate and approval logic do not change.

Persistent call reservations are consumed before network activity, including failed
requests. There are no automatic retries/resets. This is a **call-count cap**, not
an account-wide currency cap; model pricing and provider billing limits are separate.
Exact-system/evidence cache entries expire after 60 seconds and never authorize
admissions or reuse authority for merely similar payloads.

## Sandbox, intel and deployment

See [worker commands](docs/WORKERS.md), [sandbox boundary](docs/SANDBOX.md),
[Railway staging profile](docs/DEPLOYMENT.md), and [security limits](SECURITY.md).
The sandbox adapter does not supply or validate a production detonation image.
Ordinary shared Railway containers are not the isolation boundary for exploit
execution. Generated signatures remain review proposals; no automated active-rule
promotion or honeypot deployment is included.

## Why this is bounded

Current indicators cover a small, explicit corpus: two layers of URL encoding,
case/Unicode normalization, selected PHP execution/CGI indicators, suspicious RSC
prototype strings, ambiguous framing, unsupported compressed request bodies and
resource limits. They can miss attacks and flag legitimate requests. Blocking all
compressed request bodies is a conservative compatibility tradeoff, not Brotli
exploit identification. This proxy intentionally limits requests to 64 KiB and
buffers upstream responses up to 2 MiB; WebSockets, streaming/SSE, large uploads
and general-purpose transparent proxying are unsupported.

Patching vulnerable runtimes remains essential. This project is not a cure for all
PHP/Node/Next.js vulnerabilities or a substitute for application security and
tested incident response. Evaluate false positives, parser differentials, real
deployment bypasses, recovery and sustained load on staging before protecting a
real system. The first useful milestone is reproducible scoped containment, not
an AI allowed to rewrite production security policy from attacker-supplied text.
