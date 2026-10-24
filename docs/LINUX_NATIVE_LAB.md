# Private Linux native-integration pilot

This is an operator-hosted test of real, unmodified Mothership 0.3.0 and the
released DeadBolt 2.0.0 Linux executable. The analyst is a deterministic fixture.
The tester receives a standard-library HTTP client and instructions, not the
Mothership wheel, image, source, Docker socket, operator key or a shell account.
The public glue remains Apache-2.0; this does not redistribute the private engine.

## What the tester controls

The tester selects one of six fixed scenarios and advances the `ready`,
`healthy` and `detected` phases. At `approval_pending`, only the separate
operator credential can approve or reject. Unknown scenarios, targets, paths
and extra fields are refused. A revision is required for each step/decision;
stale or repeated commands cannot silently become the next action.

| Scenario | Expected observations |
| --- | --- |
| `kill` | Normal request 200, inert indicator 403, native approval, actual MCP kill, next request 503 with no extra upstream request. |
| `deny` | Same sequence with an actual clip of fixed `web.forward`. |
| `revoke` | Same sequence with revocation of the fixed admission credential. |
| `reject_approval` | Operator rejects; native target evidence is unchanged before further probes; forwarding remains 200. |
| `restart_pending` | Mothership restarts with a pending approval; that approval is then executed through the real MCP/native path. |
| `unavailable` | Missing credential, damaged disposable lease table and stopped gate each return 503 with zero upstream requests. |

Each control scenario also executes the unavailable probes in fresh fictional
target state. Approved control scenarios verify original-key receipt replay
without a second native event. Every successful receipt verifies child-process
and disposable-store cleanup. A completed run ends its target, not the separate
lab API. Kill applies to the next cooperative admission, not running OS processes.

## Operator setup

Use a dedicated Linux VM/host. The checked local Mac configuration uses Colima
with an aarch64 Linux VM and Rosetta for the Linux amd64 process. It is **not** a
native x86-64 hardware benchmark or Ubuntu/WSL server validation.

The local VM was created without host directory mounts or SSH-agent forwarding:

```sh
colima start --profile swarm-lab --arch aarch64 --vm-type vz --vz-rosetta \
  --cpu 2 --memory 3 --disk 12 --root-disk 12 --mount none \
  --ssh-agent=false --ssh-config=false --activate=false
```

Install `build` into an operator build venv. Obtain the Linux release archive and
SHA256SUMS from DeadBolt's official v2.0.0 release. Review the artifact source;
a hash and checksum downloaded from the same release establish consistency,
not independent authenticity. Keep the canonical Mothership checkout clean.

```sh
python lab/build_private.py \
  --mothership-source /absolute/path/to/authorized/mothership \
  --deadbolt-archive /private/artifacts/deadbolt-2.0.0-x86_64-unknown-linux-gnu.zip \
  --checksums /private/artifacts/SHA256SUMS \
  --out /private/swarm-lab-build \
  --host-description 'Actual host, VM and emulation details'

docker --context colima-swarm-lab build --platform linux/amd64 \
  -f /private/swarm-lab-build/lab/Dockerfile \
  -t nexteleven/swarm-native-lab:20261024 /private/swarm-lab-build
```

The builder records actual source-file, wheel and native binary hashes. Its
Docker context is an explicit allowlist. It copies no provider credentials,
personal directories, Mothership repository or application stores. The private
image still contains readable Mothership implementation: **never push, export
or send it to a tester**. It is retained solely on the operator's machine.

```sh
python lab/run_local.py start --context colima-swarm-lab \
  --private-dir /private/swarm-lab-session \
  --vm-ssh-config /absolute/path/to/colima-swarm-lab/ssh.config
```

The lab runs as UID 10001, with a read-only container root, bounded CPU/memory/
PIDs, no extra capabilities and temporary state. Its Docker network is internal;
no container ports are published. A local operator-only SSH forward through the
dedicated VM exposes only the API at `127.0.0.1:18765`. This SSH account/forward
belongs to the operator and is not given to the tester. No lab host folders are
mounted. A separate read-only volume holds session credentials, not engine keys.

There are distinct owner-only `tester.key` and `operator.key` files, a 30-minute
API lifetime, at most 24 runs, one active run, and a 45-second wait per step.
Keep both people ready before starting. No action renews a native lease or
changes a hard deadline. Use a new session if it expires.

## Operator self-test and decisions

```sh
python lab/smoke.py --private-dir /private/swarm-lab-session \
  --out /private/evidence/native-http-smoke.json
```

This is NextEleven-controlled two-role automation, not Pankaj's independent test.
It tests all six native scenarios and checks that a tester cannot decide an
approval and a repeated decision is refused. Keep its receipt separate from a
later external tester's report.

During a human session, the tester supplies the run ID and current revision:

```sh
python scripts/linux_lab_client.py --token-file /private/swarm-lab-session/operator.key \
  operator-status RUN_UUID
python scripts/linux_lab_client.py --token-file /private/swarm-lab-session/operator.key \
  operator-approve RUN_UUID REVISION
# For reject_approval, use operator-reject instead.
```

The operator's decision invokes the actual Mothership owner approval endpoint.
The tester credential has no owner privilege. Tests cannot accept arbitrary
native targets, URLs, commands or files. Exceptions return a bounded failure
code; operator-only error logs, if any, remain inside the disposable container.

## Remote session boundary

Use an operator-controlled TLS tunnel to the localhost API for an attended test.
The tester receives only its temporary HTTPS origin and tester credential through
an agreed private channel. Keep the operator credential local. The tunnel's TLS
provider is part of the transport trust boundary and may observe transit data;
use only synthetic inputs and short-lived tokens. Never expose Mothership,
DeadBolt, the Docker daemon or the protected origin directly. Do not disable
certificate verification. Close the tunnel when the session ends.

The tester kit contains no endpoint, credential or private engine. A successful
local test does not establish remote connectivity; verify the actual HTTPS
transport before inviting a tester. An external report describes observations
against an operator-hosted lab, not independent self-hosted reproduction.

## Teardown and remaining limits

Stop the temporary public tunnel first, then:

```sh
python lab/run_local.py stop --context colima-swarm-lab \
  --private-dir /private/swarm-lab-session
colima stop --profile swarm-lab
```

Stop removes only the labelled disposable container/network/credential volume,
the local forward and session key files. It retains the private image and
operator evidence for a later fresh session. Confirm no tunnel or forward
remains. Failed startup must be cleaned up with stop before another attempt.

This pilot makes zero model-provider calls and executes no real exploit. Live
analyst quality, threat-feed integration, hostile-payload sandbox isolation,
sustained load, production recovery and application deployment remain separate
validation scopes. The containers and VM here are for inert integration tests,
not a claim that they are a qualified malware-detonation sandbox.
