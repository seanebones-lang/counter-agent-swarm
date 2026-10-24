# Developer-preview glossary

| Term | Meaning and limit |
| --- | --- |
| Public component suite | Explicitly selected tests runnable without either engine or a model key. Fixtures check glue behavior; they do not prove native enforcement. The original tester archive has 69 tests; later revisions add lab access-boundary checks. |
| Native integration | Separately scoped tests using real, separately authorized Mothership and DeadBolt artifacts. This is different from the public component suite. |
| Mothership | The external orchestration runtime supplying scopes, approvals, memory and dispatch. It remains private; this repository's Apache-2.0 license does not grant runtime access. |
| DeadBolt | The external enforcement engine. Its native policies and stores decide whether a cooperative admission is allowed. |
| Admission | A permission check before the proxy forwards a request. A new request needs a fresh allow. Direct access to the origin bypasses this cooperative boundary. |
| `swarm.kill` | An approved control action that kills the configured target run and denies subsequent admissions. It does not kill OS processes or stop code already running. |
| `swarm.deny` / clip | An approved action that disables the configured `web.forward` tool for the fixed target. A clip is this bounded permission restriction, not a video clip. |
| `swarm.revoke` | An approved action that revokes the configured admission credential. It does not revoke every credential or rotate provider API keys. |
| Fixed target | The operator selects the run, tool and credential in trusted configuration. The model cannot supply arbitrary targets through these tools. |
| Next-admission-only | Control effects apply at the next cooperative check. Already admitted requests and already executing malicious code are not undone. |
| Evidence | Bounded event records and returned receipts. Local records are not independent custody or proof that a remote tester executed the reported commands. |
| Fail closed | Missing, invalid or unavailable authorization cannot allow forwarding. This may deliberately make the protected service unavailable. |
| Sandbox fixture | An inert test substitute for the adaptation boundary. The preview does not validate hostile-payload detonation or production sandbox isolation. |

The model can recommend an action; Mothership's native approval is still required.
See the README for the complete trust boundaries and unvalidated deployment scope.
