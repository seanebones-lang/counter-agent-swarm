# Verified development checkpoint

## Evidence at a glance: October 24, 2026

These are separate observations with overlapping tests, not additive totals.

| Evidence | Recorded result | What it establishes and what it leaves open |
| --- | --- | --- |
| [Current packaged component CI](https://github.com/seanebones-lang/counter-agent-swarm/actions/runs/40133102523) | 76 public tests passed in each of three ordinary-user jobs: Ubuntu Python 3.12/3.13 and macOS Python 3.13. | Public source distribution builds and installs outside the checkout without Mothership. Does not exercise private native engines or live model judgment. |
| [Pankaj Basnet's external component report](../CONTRIBUTORS.md#pankaj-basnet) | Reported 69 earlier public tests passing on Ubuntu 24.04/WSL2, Python 3.12.3, as root. | External installation feedback improved setup instructions, glossary and the ordinary-user follow-up. This is self-reported component evidence; ordinary-user WSL and his native-integration test remain pending at this checkpoint. Private report files and contact details are not published. |
| [NextEleven-controlled Linux regression and native lab](linux-lab-validation.json) | 101 installed regression tests passed, one optional duplicate native test skipped; six native scenarios executed separately. | Real unmodified Mothership 0.3.0 and released DeadBolt 2.0.0, UID 10001, synthetic requests. Linux amd64 userspace ran under Rosetta in an aarch64 Linux VM on Apple Silicon; this is not native x86-64 performance or WSL server validation. |
| [Native lab scenario and transport details](LINUX_NATIVE_LAB.md) | Kill, deny, revoke, rejected approval, pending approval across restart and unavailable/damaged/missing gate cases passed. An additional native kill passed through temporary HTTPS. | Operator-controlled two-role checks with a deterministic analyst and zero live model calls. This is separate from an external tester's observations; it is not security certification, hostile-payload isolation or production validation. |

The [original packaged CI](https://github.com/seanebones-lang/counter-agent-swarm/actions/runs/40060498003)
retains the earlier 69-test Ubuntu/macOS Python 3.13 baseline. Keep that history
separate from the expanded 76-test suite. For reproduction and current limits,
use the [pilot guide](PILOT_TEST_GUIDE.md), [Linux lab guide](LINUX_NATIVE_LAB.md)
and the detailed checkpoints below. The public glue is Apache-2.0; Mothership
remains private and is not distributed in the public tester kit.

## October 24: operator-hosted Linux native lab

The [private Linux lab](LINUX_NATIVE_LAB.md) now runs real unmodified Mothership
0.3.0 and released DeadBolt 2.0.0 Linux x86-64 behind separate tester/operator
credentials. Six native scenarios passed through the restricted HTTP interface:
kill, deny, revoke, rejected approval, pending approval across a Mothership
restart, and unavailable/damaged/missing gate prerequisites. A native kill also
passed through a temporary verified HTTPS tunnel while the operator credential
remained on loopback. The exact extracted tester client reached that HTTPS plan.

The test host was an aarch64 Linux VM on Apple Silicon, running Linux amd64
userspace with Rosetta. This is not a native x86-64 performance result or a WSL
server test. All integration tests ran as UID 10001 with synthetic requests and
zero live model calls. The Linux installed regression run passed 101 tests with
one optional native test skipped; native scenarios were executed separately.
The newer public component subset has 76 passing local tests, including lab
access-boundary checks. These scopes overlap and must not be added together.

The [scoped validation record](linux-lab-validation.json) retains engine/artifact
hashes, scenario outcomes and limits. Tester-kit inspection confirmed the kit
contains only client, instructions, feedback form and license/hash files. No
private engine or credential was distributed. Native cancellation returned
through cleanup with no child engine processes left. The temporary public
tunnel and disposable session were closed after verification; a fresh attended
session is needed for a tester. Pankaj has not yet performed this native test.

Live analyst quality, actual threat-feed delivery, hostile-payload analysis,
production deployment/load/recovery and independent adversarial assessment
remain unvalidated. The native pilot uses a deterministic analyst fixture.

## Earlier local integration checkpoint

The first local Counter-Agent Swarm integration milestone is implemented. This
is a new glue repository; neither Mothership nor DeadBolt was forked or modified.

Verified on macOS arm64 with external unmodified Mothership 0.3.0 and native
DeadBolt 2.0.0:

- Built a glue-only wheel and installed it into a temporary directory outside
  the checkout. All 94 regression tests passed there after the release fixes.
- Ran the separate native acceptance from that installed package: kill,
  clip-forwarding deny, credential revocation, and unavailable/damaged gate cases
  passed. The ordinary pytest native test is skipped unless explicitly opted in;
  native acceptance was executed separately, not omitted.
- Recomputed the source fingerprint and retained the wheel hash and redacted
  receipts in `acceptance.json` and `package-validation.json`.
- Native approvals and same-key receipts were verified; the analyst in native
  acceptance was a deterministic fixture, not a live model.
- Temporary acceptance services/stores were removed. Canonical Mothership's
  tracked source remained clean.
- Approved OpenAI credential saved in private ignored local configuration; no
  credential value is included in this repository. Zero Swarm OpenAI requests.
- Hermes with Grok4.7 actually ran the fixed installed-package, regression and
  native acceptance commands through a restricted QA MCP. The passing run used
  seven xAI requests; this is an external test driver, not a live Swarm analyst.
  See `HERMES_TEST_REPORT.md` for the first kit failures, corrections and limits.
- A new environment containing only public glue dependencies passed69 component
  tests without Mothership installed. `scripts/test_glue_only.py` and the pilot
  guide make this narrower test available without disclosing the private engine.
- The completed source security scan found one medium path-representation
  screening bypass in the original1036d76 snapshot. The subsequent local fix
  screens the ASGI path and preserves encoded forwarding;14 proxy cases cover
  the fix, including zero gate/upstream calls for blocked variants. The original
  scan remains sealed and is not a scan of the changed tree.
- Operator-only completed-record archival preserves unsettled incidents and
  supports bounded queue maintenance. The staging supervisor delays the public
  listener until control readiness and sets explicit connection/resource bounds.

Implemented but validated with fixtures/mocks only: frontier Responses adapter,
native analysis approval wrapper, incident ingress/queue/worker recovery phases,
intel handoff, sandbox host adapter and immutable rule proposals. These are not
evidence of effective model judgment, live threat-feed delivery or actual sandbox
isolation. The sandbox adapter requires a separately reviewed analyzer image and
dedicated host; this repository supplies neither an exploit image nor a live
detonation environment.

The Dockerfile, supervisor and Railway instructions are a staging profile;
production deployment, sustained attack load, actual backup restoration,
private-origin bypass resistance and independent adversarial testing have not
been validated. The Apache-2.0 glue repository was published on October 23, 2026:
https://github.com/seanebones-lang/counter-agent-swarm . An anonymous HTTPS clone
succeeded. Public CI built and installed the source distribution outside the
checkout and passed all69 component tests on both Ubuntu and macOS with Python
3.13: https://github.com/seanebones-lang/counter-agent-swarm/actions/runs/40060498003 .
This establishes public component packaging, not Linux native-engine deployment.
Mothership remains private. No package-registry release or cloud service was
created, and no live application traffic was changed.

The architecture keeps native human approvals for model analysis and system-wide
control. Suspicious requests are blocked immediately by deterministic code.
Proposals cannot update active detection automatically. DeadBolt controls the next
cooperative admission, not in-flight work or processes already compromised.
