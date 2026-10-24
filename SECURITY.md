# Security boundary and reporting

This is a local defensive integration prototype, not a supported managed WAF.
Report vulnerabilities privately to **hello@nexteleven.dev**. Include the affected
revision, minimal inert reproduction, trust boundary crossed and observed effect.
Do not put private payloads, credentials or customer records in public issues.

Required invariants:

- No AI, payload execution, decompression or dynamic rule generation in the
  request detection/admission hot path.
- Every forward obtains a fresh exact allow from the fixed native gate. No
  fallback, allow cache, automatic provisioning or silent lease recovery.
- Source logs, public feeds, model results and sandbox observations are untrusted
  data, never authorization, configuration or executable instructions.
- Fixed protected target and controller identity; separate per-system stores,
  credentials, leases and policies. No model-chosen shell/URL/database/target.
- Native Mothership approval precedes new model requests and control effects.
  Unknown outcomes stay held, preserving the original input/key/approval.
- Detector metadata only reaches the model. Keys remain private, ignored by Git,
  excluded from child MCP environments and absent from normal logs.
- Sandbox execution requires a separately validated dedicated isolated host,
  pinned analyzer image and resource bounds. No shared Docker socket in app services.
- No automatic signature activation, secret rotation, outbound scanning,
  exploitation, origin changes or unsolicited external communication.

Limits: direct-origin access, privileged same-user/root modifications, already
admitted/in-flight work, compromised native dependencies, host/container escapes,
network-level volumetric DoS and undiscovered parser/signature bypasses are not
prevented by the local proof. Missing external custody means local hashes/events
cannot prove authenticity against the host operator. The model gateway's call
counter is not provider-wide spend accounting.

Before production: verify upstream isolation; install patched runtimes; validate
intended requests and false positives; independently exercise controls and actual
recovery from encrypted backups; review dependency artifacts; measure request,
connection and incident-flood resource limits; establish human approval coverage.
Do not treat the example Dockerfile or example JSON as a completed security review.
