Counter-Agent Swarm: voluntary private-hosted native-integration test
NextEleven — Apache-2.0 public client; private engines stay with the operator

Thank you for helping. This is a voluntary 20–30 minute attended test. Stop any
time, and report unclear instructions or unexpected behavior. No source changes,
provider account, paid service, Mothership installation or administrator access
is needed. Use Python 3.12 in your WSL/Linux environment. Native Windows client
file-permission handling has not been validated.

Before starting, NextEleven will arrange a time and give you a temporary HTTPS
origin and a short-lived tester key through an agreed private channel. This kit
intentionally contains neither. Do not request or use an operator key, image,
Mothership wheel, shell account, production endpoint or real exploit. Review
client.py before running it. Verify the kit checksum NextEleven supplies.

1. Save only the tester key in a file named tester.key in a private Linux-home
   directory. Use umask 077 before creating it, and chmod 600 tester.key. Never
   paste the key into a shell command, screenshot, report, repository or chat.
2. In the commands below, replace HTTPS_ORIGIN with the provided HTTPS origin.
   Run:

   python3 client.py --url HTTPS_ORIGIN --token-file tester.key plan

   Record the manifest, OS/architecture/emulation statement and engine versions.
   The server uses real Mothership 0.3.0 and DeadBolt 2.0.0 with a deterministic
   analyst fixture. This does not test live AI judgment or hostile detonation.

3. Test these scenarios separately: kill, deny, revoke, reject_approval,
   restart_pending, unavailable. Start the first with:

   python3 client.py --url HTTPS_ORIGIN --token-file tester.key start kill

   Record the returned run_id. Use that UUID in place of RUN_UUID below:

   python3 client.py --url HTTPS_ORIGIN --token-file tester.key status RUN_UUID

4. At ready, healthy and detected, read the observations. Advance using the
   revision from the latest status (replace REVISION with its integer):

   python3 client.py --url HTTPS_ORIGIN --token-file tester.key step RUN_UUID REVISION

   Refresh status after every step. A stale revision is intentionally refused.
   There is a 45-second wait at each step, so read these instructions first and
   keep the operator available. A timed-out run is useful feedback; start a new
   run rather than altering tests or extending permissions.

5. At approval_pending, stop advancing and tell the operator the run ID and
   revision. Only the operator can decide. For reject_approval the operator
   rejects; for the other control cases the operator approves. Record what you
   observed before and after the decision. Your key cannot approve an action.

6. Expected normal sequence: 200 with one fictional upstream request, then 403
   for the inert indicator without another upstream request, pending approval,
   then 503 after approved kill/deny/revocation. Same-key replay must not create
   a second native event. Rejection must leave normal forwarding working (200).
   restart_pending checks an approval preserved across a Mothership restart.
   unavailable checks missing credentials, a damaged disposable lease table and
   a stopped gate: each must deny with no upstream request. These failure probes
   also run after each control scenario in separate fictional target state.

7. A passed run includes a receipt confirming process and disposable-store
   cleanup. Save each final status as a new JSON file, for example:

   python3 client.py --url HTTPS_ORIGIN --token-file tester.key status RUN_UUID > kill-result.json

   Never replace an earlier failed report with a later passing one. If something
   fails, retain the first error/status and tell the operator. Do not try real
   attacks, supply different URLs/targets, or change source to force a pass.

8. Return the six result files plus completed FEEDBACK.txt by reply email after
   inspecting/redacting them. Never include tester.key, operator keys, .env,
   unrelated logs or customer data. Report any redactions. Nothing uploads
   automatically. With your existing consent we can retain hashes/provenance;
   this cannot independently attest remote execution or security.

9. When finished, tell the operator. They close the tunnel and remove the
   disposable session and keys. Remove your temporary tester key when no longer
   needed; retain only the redacted results you intend to share.

This is independent feedback against a NextEleven-hosted lab. The operator
retains custody of the runtime. It is not independent self-hosted reproduction,
a security certification, production readiness or broad exploit coverage.
