# Hermes/Grok test-driver evidence

This is an agent-driven invocation of fixed test tools, not an independent
security assessment or a live test of the Swarm response analyst. The provider
relay recorded only `grok-4.7` requests to xAI, with no fallback. Hermes had a
private profile and only the two fixed QA MCP tools; no host shell or arbitrary
file reader was offered to the model. The real xAI key stayed in the relay.

The first kit omitted `examples/`, which broke native fixtures. Its shared-mode
test also relied on mkdir's requested mode despite an inherited umask077. The
corrected fixture explicitly chmods0755 before asserting refusal. That initial
fixture result did not demonstrate acceptance of an actually shared directory;
the first model report overinterpreted it. Both test-kit defects were corrected
before the passing run below. An intervening driver launch made zero provider
calls because its reused private Hermes gateway retained an obsolete temporary
relay credential. Restarting only that QA profile resolved it. No provider key
was rejected by xAI.

The passing run made seven xAI requests and actually executed all three fixed
test commands, confirmed by separate tool-execution records. Across the first
and passing runs, fourteen xAI requests were made. Neither run enabled the
Swarm OpenAI analyst. The optional skipped regression is the duplicate native
acceptance test; the standalone native proof was executed successfully. The
private QA profile's gateway was stopped after the test.

## Passing driver's verbatim report

Counter-Agent Swarm — external developer-preview test note
Date: 2026-10-24. Driver: Hermes as external test runner only. Tools: swarm_qa test_plan, then run_test for distribution, regressions, native_acceptance. No other tools. Three invocations of four allowed.

Verdict: all three allowlisted cases exited 0. That is local synthetic proof only. It is not production readiness, not comprehensive protection, and not a live model trial of the Swarm AI response layer. native_acceptance sets model_operated false and live_model_calls 0. Recommendations in that path are deterministic fixtures. I did not exercise a frontier model.

PASS/FAIL

distribution — PASS (exit 0, 0.05s).
Observed: installed_import true; module path under the kit installed tree (<QA>/kit/installed/counter_swarm/__init__.py); source_checkout_imports false; provider_keys_in_kit false. Manifest: wheel_sha256 ff7ceda3e0ca25005694eda191a107b7efb2449fe62a9cef2fb17a0af7b10d3e; glue_source_sha256 0de3e51286a8dece1b1bfc0aac41bc4cd701970abcd36ff42278982181715887; runtime Python 3.13.13; mothership "0.3.0, external private runtime, not included in kit"; deadbolt "2.0.0 external macOS arm64 executable"; dependencies note says preexisting Mothership venv, not a fresh install. README excerpt states status as local synthetic integration proof, not production protection, and says the analyst in that proof is a deterministic fixture.

regressions — PASS (exit 0, 7.45s wall, pytest 6.60s).
Observed stdout: 94 passed, 1 skipped. No failure lines. Plan scope: installed-wheel regressions for deterministic detector, proxy, fail-closed gate, queue, budgets, and worker state. Skip reason was not printed.

native_acceptance — PASS (exit 0, 9.38s).
Observed summary: status passed, scenario_count 4, model_operated false, receipt <QA>/native-from-hermes.json.
Receipt checked_at_utc 2026-10-24T03:19:55Z. glue_source_sha256 matches the distribution manifest. deadbolt 2.0.0, binary sha256 741f7f60966b56c7ce1f3d2268778c6bdb69f0ece23c6992980dc3708d134fd1. mothership 0.3.0, source revision 7daf8ddd33c148853f88412c4409c4bada1f34c7, tracked source clean, unmodified external dependency true, native admission required true, control run separate from protected targets true, processes_stopped true, disposable_stores_removed true, real_accounts_or_services false, exploit_detonation false.
Per scenario (kill, deny, revoke), each: healthy 200, indicator 403, approval_required true, mothership memory verified, native MCP action verified, same-key replay without a second native event, next request 503, upstream_requests_during_scenario 1, control evidence still readable after the action, fixture_analyst_calls 1.
Fail-closed case: missing credential, unavailable store, and unavailable gate each 503; failed store not recreated; upstream requests 0.

Defects
None observed as test failures. The single regression skip is unexplained in the captured output, so treat it as an open question, not a pass of that case. The MCP distribution payload truncated the README excerpt mid-sentence ("Set t"); the case still exited 0. I did not re-read the file.

Gaps before an outside developer
From the plan and the receipt, not inferred:

- Mothership 0.3.0 is a private runtime. No public end-to-end download. Kit does not include it. Outside reviewers cannot reproduce native_acceptance without an authorized artifact.
- Native binary in this run is macOS arm64 only. Sandbox isolation and Railway/Linux deployment were not validated.
- Swarm live OpenAI analyst is disabled. Grok was only the test driver. Live frontier-model analysis was not run. Do not describe this as model-tested response quality.
- Kill, clip-deny, and revoke block the next cooperative admission. They do not stop in-flight HTTP, OS processes, or code already running.
- Indicators are conservative examples, not exploit coverage. No hostile-payload detonation.
- No deployment, OS sandbox, live WAF rollout, public-origin bypass, performance-under-attack, or independent adversarial evaluation.
- Direct access to a non-private origin bypasses a cooperative proxy. Same-user or root edits of credentials, policies, binaries, or stores are outside the enforcement boundary. Events are local records, not independent custody.
- This is same-team protocol automation against disposable loopback stores, not an outside lab.

Do not ship this note as a claim of protection.

