# Verified development checkpoint

The first local Counter-Agent Swarm integration milestone is implemented. This
is a new glue repository; neither Mothership nor DeadBolt was forked or modified.

Verified on macOS arm64 with external unmodified Mothership 0.3.0 and native
DeadBolt 2.0.0:

- Built a glue-only wheel and installed it into a temporary directory outside
  the checkout. All 62 regression tests passed there.
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
  credential value is included in this repository. Zero live model requests.

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
