# Railway or equivalent: isolated per-system staging

The included Dockerfile is a **deployment template**, not a built/published image
or a validated Railway deployment. The retained native proof ran on macOS arm64.
No Railway service, subscription or paid hosting resource was created. Test this
profile on a disposable patched Linux target before assigning a real origin.

## Why the initial profile is colocated

Mothership 0.3.0's native DeadBolt binding requires an explicit literal loopback
HTTP URL. Its adapter cannot point at an arbitrary Railway private-DNS sidecar.
Consequently the first supported topology colocates these small processes in a
single **dedicated per-system control/edge service**:

- DeadBolt authenticated admission sidecar on 127.0.0.1:9782.
- Unmodified Mothership with glue tools on 127.0.0.1:9783.
- Metadata-only ingress on 127.0.0.1:9784.
- Stateless edge proxy on the platform's public `PORT`.
- One-shot incident worker invoked serially by the small process supervisor.

Only the edge port is public. The actual application is a separate private
service. Turn off its public domain/external ingress and verify it cannot be
reached around the proxy. If private network placement cannot guarantee that,
this deployment does not provide the intended enforcement boundary.

The supervisor launches processes, observes exit and stops children together. It
does not implement an agent brain, renew authority, approve changes, provision
leases or retry held incidents. A dead required child stops the whole group.
Never put an exploit-execution container or Docker socket in this service.

The supervisor supplies an explicit environment to every child. Only Mothership
receives the current OpenAI analyst credential, master/bootstrap keys and its
named settings. Edge, ingress and the incident worker receive only their runtime
configuration path plus deliberate process runtime values. DeadBolt receives its
own operator token and bound database/event paths. Arbitrary provider variables,
unlisted `MS_`/`COUNTER_SWARM_` names, Python import hooks and proxy/certificate
overrides are not inherited. See `child_environment.py` for the exact static
grants; introducing an additional setting requires an operator-reviewed policy
change. Install the reviewed distribution: a development `PYTHONPATH` is not a
supported child import mechanism. Only the fixed OpenAI adapter is currently
implemented; unrelated/custom provider credentials are not automatically passed.

This reduces environment exposure, not filesystem/process authority. The roles
still share a UID/container and can access same-user files. In particular, the
runtime JSON names private credential files, and external Mothership may read a
`.env` file from its working directory after startup. Keep the installed working
directory trusted and free of unrelated `.env`/user-controlled config. Environment
filtering does not disable that dependency behavior, validate trusted executables,
or replace separate users/containers, immutable configuration and origin isolation.

## Prepare external artifacts privately

1. Obtain the authorized unmodified Mothership 0.3.0 wheel and a reviewed native
   DeadBolt 2.0.0 **Linux** binary for the target CPU. The Mac binary from local
   acceptance cannot run in the Linux image. Verify origin, licenses and hashes.
2. Place only those reviewed build inputs in ignored `dependency-artifacts/`.
   It must contain the Mothership `.whl` (plus any separately required private
   wheel dependencies) and an executable named `deadbolt`. Engine source remains
   external; do not copy it into this repository or change either license.
3. Build the provided Dockerfile with a trusted builder. This image includes a
   proprietary dependency: keep the image private and respect Mothership's license.
   Do not upload private artifacts to a public image registry or public source repo.
4. Pin the base image/dependency artifacts for a reviewed release, retain a
   dependency inventory and verify the resulting installed image. The example
   floating Python base tag is for staging, not a supply-chain attestation.

## Provision one private instance

Attach a persistent volume, e.g. `/data`; prepare `/data/private` owned by UID10001,
mode0700, before starting the non-root image. Files must be UID10001, mode0600.
Do not loosen file permissions merely to make a volume mount work. Back up the
entire consistent stopped state, encrypt the backup and test restoration on a
separate volume before protecting a real application. No actual recovery drill
has been performed for this deployment template.

Copy and edit the three example binding/runtime JSON files. Configure the paths
in `.env.example` through platform variables. Supply random independent secrets:

- `DEADBOLT_TOKEN`: sidecar operator credential, never a model tool argument.
- Native target admission credential: private `target.token`.
- Native controller admission credential: private `controller.token`.
- Random incident-ingress token: private `ingress.token`.
- Mothership owner/master secrets required by the reviewed external installation.
- Dedicated controller's agent key: private `mothership-agent.key`.
- Optional model key only when an explicit live-call allowance is approved.

Use DeadBolt's existing operator CLI to provision a **fixed-deadline target run**
and a separate controller run, each with its own policy and credential. The target
allows only `web.forward`. The controller allows only the glue tools and required
memory operations shown in the README; generic `http.request` stays denied.
Keep the credentials and store binding consistent across sidecar, MCP facade,
Mothership and proxy. The `scripts/acceptance.py` provisioning code is a tested
disposable reference; it is not a script for provisioning real production authority.

Create the Mothership agent through its existing owner API using
`examples/mothership-agent.json`. Keep `MS_DEADBOLT_REQUIRED=true` throughout;
owner bootstrap is separate from agent dispatch. Put the returned actual agent ID
in both `COUNTER_SWARM_MOTHERSHIP_AGENT_ID` and the product-bindings map. Restrict
owner access to a private authenticated operator channel. The public edge must
route only to the protected application, never to Mothership/admin ingress.

Fixed deadlines/credential TTLs deliberately close the edge when they expire.
The prototype has **no automatic lease renewal**. Establish an explicit trusted
operator lease-management policy and test deadline behavior. Extending an expired
lease is an authority change, not an automatic retry or incident-worker task.

## Start, check and replicate

The image runs `python -m counter_swarm.supervisor`. Only the configured `PORT`
is exposed. Railway TLS should terminate in front of that port. Provider health
status alone is not proof of enforcement: check an intended benign request reaches
the private test origin, a bounded inert indicator does not, gate loss denies, and
owner-approved controls affect only the intended target. Verify no direct-origin
route, public owner route, copied credential or accidental broad policy exists.

Use `counter-swarm status` to inspect bounded incident IDs/states. Use native
Mothership approvals/evidence for decisions, then `counter-swarm resume --event-id
ORIGINAL_ID` to consume an existing approval result. Held/uncertain work requires
operator reconciliation and must not be reset to queued to force another effect.
Keep access logging off where URLs may contain private material; the glue's
incident logs carry only stable IDs and bounded status codes. Configure the host's
log rotation, connection/concurrency limits and alerts before any public load test.

For another protected system, duplicate the service with a **new volume, identity,
target/controller runs, independent credentials and policies**. Never share a
control binding or model-call budget file across otherwise independent systems.
Public/shared multi-tenancy is out of scope. This topology has not been benchmarked
under a mass-exploitation event.

The intel command is one-shot; schedule it with an existing approved scheduler
only after its live feed/memory delivery is validated. Sandbox jobs run on their
own dedicated validated host, never this Railway service. See [WORKERS.md](WORKERS.md).

Official platform reference: [Railway Dockerfile builds](https://docs.railway.com/builds/dockerfiles).
