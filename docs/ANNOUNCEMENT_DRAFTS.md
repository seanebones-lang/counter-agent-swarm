# Announcement drafts — not published

Do not post a download claim until a real public repository URL exists and its
source distribution passes the documented public component test. Do not call
the whole stack open source: the new glue is Apache-2.0, Mothership is private,
and full engine integration needs separate access. Replace `REPOSITORY_LINK`
only with the verified published URL. No production-readiness claim is approved.

## X: initial developer-preview post

I've been building Counter-Agent Swarm at NextEleven: Apache-2.0 glue for deterministic request screening, Mothership response agents and DeadBolt enforcement.

Opening a developer preview for testing and feedback. Component tests run without an API key.

REPOSITORY_LINK

### Follow-up reply

The important boundary: no AI in detection or enforcement. Model advice stays off the request path and system-wide actions require approval.

We've tested the native kill/deny/revoke loop locally. Mothership access is separate. This is an early preview, not a production WAF.

## LinkedIn

I've been building Counter-Agent Swarm at NextEleven, and I'm opening the glue layer as an Apache-2.0 developer preview.

The idea is practical: screen requests with bounded deterministic code, give a response agent scoped evidence to investigate, and enforce approved actions through DeadBolt. The model doesn't sit in the detection or enforcement path and can't approve its own system-wide actions.

Our local acceptance test uses actual Mothership and DeadBolt processes with fictional runs and inert indicators. It checks that actions wait for approval, the approved kill/deny/revoke paths block the next admission, and replaying the same action key doesn't create another control event.

I'm looking for developers who will try the component test, question the boundaries and tell me where installation or documentation breaks. You can run that test without a model account or API key. Full native integration needs separate access to Mothership, which remains private.

This is a developer preview. Linux/cloud deployment, sustained attack load, real sandbox isolation and live model judgment still need validation. It isn't a replacement for vendor patches or a production security assessment.

Code, test instructions and the current limits: REPOSITORY_LINK

Built by NextEleven. Feedback and contributions are welcome.

## Attribution and license choice

The recommendation is to keep Apache-2.0 for the glue, retain the full LICENSE
and NOTICE, and keep “Created by NextEleven” in the README. Apache provides an
express contributor patent grant and requires applicable copyright/attribution
and NOTICE preservation on redistribution. It does not require a marketing
endorsement, an on-screen logo, or public advertising credit. It does not grant
trademark rights. MIT is also permissive and requires its notice to be retained,
but does not include the same express patent terms. Do not add an advertising
clause that changes the standard license merely to obtain credit.

Primary texts: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0),
[MIT](https://opensource.org/license/mit). External dependencies keep their own
licenses; this choice does not grant distribution rights for private Mothership.
