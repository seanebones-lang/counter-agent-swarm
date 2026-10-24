# Verified development checkpoint

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
container/runtime deployment, sustained attack load, actual backup restoration,
private-origin bypass resistance and independent adversarial testing have not
been validated. No public repository, registry release or cloud service was
created. No live application traffic was changed.

The architecture keeps native human approvals for model analysis and system-wide
control. Suspicious requests are blocked immediately by deterministic code.
Proposals cannot update active detection automatically. DeadBolt controls the next
cooperative admission, not in-flight work or processes already compromised.
