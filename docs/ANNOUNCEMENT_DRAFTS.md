# Publication drafts — not posted

Prepared October 23, 2026. The GitHub glue repository is now public and its packaged component CI passes on Ubuntu and macOS. The article and social posts below remain unposted drafts. No new license grant for Mothership or production-protection claim is implied.

# Black October: Help Us Test Counter-Agent Swarm

The past few days have made something clear to me: small development teams need more practical help responding to security threats.

“Black October” is appearing in reporting about this month’s cybersecurity disclosures. [Current coverage](https://www.theguardian.com/technology/2026/oct/23/cybersecurity-ai-hacking-php-vulnerability)

The underlying issues are concrete. PHP has released fixes for two critical vulnerabilities that can allow unauthenticated remote code execution. Node.js has published security updates that include a Brotli decoder flaw capable of leading to remote code execution when an application decompresses malicious input. These are issues in infrastructure developers depend on every day. [PHP advisory](https://www.php.net/archive/2026.php), [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)

For an independent developer or a small team, another urgent advisory lands alongside everything else: shipping fixes, answering customers, paying the bills and keeping services running.

I see this as a security response crisis, especially for teams with limited time and resources. My response is to put some of NextEleven’s engineering time into a project that other developers can inspect, test and help improve.

It’s called **Counter-Agent Swarm**.

We’re building an Apache-2.0 open-source glue layer for defensive investigation and response. We want to develop it in public, show our working, publish the limits alongside the results, and invite people to challenge the design.

The source is now public: [Counter-Agent Swarm on GitHub](https://github.com/seanebones-lang/counter-agent-swarm). The repository includes the component tests, setup instructions and contribution guide.

The purpose is to explore a practical question: can we help an operator investigate suspicious activity and apply a tightly scoped response, while keeping authority clear and the request path predictable?

Here is the architecture we’re working toward:

- **Deterministic screening:** bounded code checks requests and flags supported suspicious patterns without calling an AI model.
- **Scoped investigation:** Mothership manages the response agent’s tools, evidence, approvals and resumable work.
- **Explicit enforcement:** DeadBolt applies approved actions to a fixed target, such as refusing later admissions or revoking a credential.
- **Separate adaptation and intelligence:** isolated analysis and public threat information produce material for review. Proposed rules do not automatically become active defenses.

The important boundary is that **AI stays out of detection and enforcement**. A model can recommend a system-wide action, but it cannot approve its own action or grant itself more authority. If the forwarding gate cannot establish permission, forwarding stops.

There are limits to what that means. DeadBolt’s kill path blocks the next cooperative admission. It cannot undo a request already running or remove malicious code from an already compromised machine.

We also need to be precise about “open source.” The new Swarm glue is Apache-2.0, and DeadBolt is a separate Apache-2.0 dependency. Mothership currently remains a private dependency. The component preview can be tested without it; the complete native integration needs separately authorized runtime access. We’re not presenting the entire stack as publicly available.

**There is a working local proof, and there is more to validate.**

Our current local checks include 94 passing regression tests. Within that set, 69 component tests can run without Mothership, a DeadBolt executable or a model API key.

A separate four-scenario acceptance test uses actual Mothership and DeadBolt processes. It checks approval before an effect, the native kill/deny/revocation paths, replay without a duplicate control event, and refusal when the gate or its required state is unavailable.

We also used Hermes with Grok as a restricted test driver to run the fixed checks. That is useful repeatability evidence. It is not an independent security assessment or proof of the response model’s judgment.

Linux/cloud deployment, sustained attack load, actual sandbox isolation and live analyst judgment remain open validation work. The current indicators are examples, not comprehensive exploit coverage. Patching, sound infrastructure configuration and established security controls remain essential.

Those limits are part of why we’re asking for help now.

**We’re looking for volunteer testers and contributors. This is unpaid.**

This invitation is for voluntary open-source participation. It is not a paid role or an internship offer. Please contribute only the time you choose; there is no ongoing commitment.

You could help by:

- Running the component preview on a clean environment and reporting the first installation or test failure.
- Reviewing Python/backend code, request handling, permissions or failure behavior.
- Helping evaluate Linux and container behavior in an authorized local environment.
- Improving instructions, examples and error messages so another developer can reproduce the results.
- Challenging our claims and pointing out where the evidence falls short.

You don’t need to be a security expert to discover that our setup instructions don’t work on your machine. That feedback matters.

For a first test, allow roughly 30–45 minutes. The component suite uses fictional data and local or mocked fixtures. It needs no paid account or API key. A results collector writes a local report, test output and feedback template; it uploads nothing.

We ask testers to return what happened, including failures, their environment, and any changes they made. With permission, we can preserve returned reports and file hashes in a private Witness provenance record. That records what we received; it does not certify that a report is true or that the software is secure.

We would be happy to credit people who assist as **official project contributors and testers**, using their preferred name or GitHub handle and with their agreement before public acknowledgement.

Start with the [code and test instructions](https://github.com/seanebones-lang/counter-agent-swarm) and [contribution guide](https://github.com/seanebones-lang/counter-agent-swarm/blob/main/CONTRIBUTING.md). If you'd like help choosing a scope, email **hello@nexteleven.dev** with the subject **Counter-Agent Swarm — testing or contributing**. Tell us your OS, CPU architecture, and the kind of help you're interested in.

The intent is straightforward: build something useful, make the work inspectable, listen to people who find problems, and improve it in the open.

If you can help us find where it breaks, we’d be grateful.

**Sean McDonnell, NextEleven**

---

## Short X introduction

NextEleven's response to Black October: Counter-Agent Swarm.

Apache-2.0. Seeking volunteer testers/contributors (unpaid; credit by agreement). 69 component tests; no API key.

https://github.com/seanebones-lang/counter-agent-swarm

## LinkedIn introduction

The security disclosures being called “Black October” have pushed me to put more of NextEleven’s engineering time into practical defensive tooling.

We’re building Counter-Agent Swarm, an Apache-2.0 glue layer connecting deterministic request screening, scoped investigation through Mothership, and explicit enforcement through DeadBolt.

AI stays out of detection and enforcement. System-wide model-recommended actions require approval.

We’re inviting volunteer testers and contributors. This is unpaid open-source participation, with optional public credit as an official project contributor or tester.

The component preview has 69 tests and needs no API key, paid account or access to a real application. We’re looking for clean-environment tests, Python/backend review, Linux/container feedback and clearer documentation.

The public repository and test instructions are live: https://github.com/seanebones-lang/counter-agent-swarm . Mothership remains a separate private dependency, so full native integration needs additional runtime access.

This is an early developer preview. Production deployment, real sandbox isolation and live analyst judgment still need validation.

If you’d like to help, email hello@nexteleven.dev with your OS/CPU and the area you’re interested in. Honest failure reports are welcome.

The article below explains what we’re trying to do, what has been tested and where we need help.

#OpenSource #CyberSecurity #Python #BuildInPublic
