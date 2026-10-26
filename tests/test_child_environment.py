"""Actual supervisor spawn boundaries, using inert children and fictional grants.

The driver has its own environment. No process-global environment mutation or
private engines, real listeners, provider requests or operator secrets are used.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]
ROLES = {"deadbolt", "mothership", "ingress", "edge", "worker"}


PROBE = """
import json, locale, os, pathlib, shutil, sys, tempfile, time
output, role = sys.argv[1:]
with tempfile.NamedTemporaryFile() as temporary:
    temp_ok = pathlib.Path(temporary.name).parent == pathlib.Path(os.environ['TMPDIR'])
data = {'role': role, 'names': sorted(os.environ), 'temp_ok': temp_ok,
        'path_ok': shutil.which('python') is not None,
        'lang_ok': os.environ.get('LANG') == 'C',
        # Python may coerce C to a supported UTF-8 locale at interpreter startup.
        'ctype_ok': bool(locale.setlocale(locale.LC_CTYPE, os.environ['LC_CTYPE'])),
        'readiness_marker': os.environ.get('MS_DEADBOLT_REQUIRED')}
pathlib.Path(output).write_text(json.dumps(data))
time.sleep(60)
"""


DRIVER = """
import json, pathlib, signal, subprocess, sys, time
from types import SimpleNamespace
root, workspace, scenario = map(str, sys.argv[1:])
sys.path.insert(0, str(pathlib.Path(root) / 'src'))
from counter_swarm import supervisor
from counter_swarm.gate import Gate
import httpx
workspace = pathlib.Path(workspace)
config = SimpleNamespace(target_run='fixture', gate_origin='http://127.0.0.1:9782',
    mothership_origin='http://127.0.0.1:9783', ingress_origin='http://127.0.0.1:9784',
    admission_token_file='not-read')
binding = SimpleNamespace(target_run='fixture', forward_tool='web.forward',
    deadbolt_binary='fictional-deadbolt', lease_ttl_seconds=300,
    child_env=lambda: {'DEADBOLT_DB': 'fictional-db', 'DEADBOLT_EVENTS': 'fictional-events'})
supervisor.RuntimeConfig.load = lambda: config
supervisor.ControlBinding.load = lambda: binding
handlers, children, roles, observed = {}, [], [], []
supervisor.signal = SimpleNamespace(SIGTERM=signal.SIGTERM, SIGINT=signal.SIGINT,
    signal=lambda number, handler: handlers.update({number: handler}))
async def admitted(_):
    observed.append('gate')
    return scenario != 'gate_down'
Gate.admitted = admitted
def health(*args, **kwargs):
    observed.append('health')
    return SimpleNamespace(status_code=200)
httpx.get = health
if scenario == 'gate_down':
    clock = iter([0, 21])
    supervisor.time = SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None)
real_popen = subprocess.Popen
def launch(argv, **kwargs):
    if argv[0] == 'fictional-deadbolt': role = 'deadbolt'
    elif 'counter_swarm.mothership_ext:create_app' in argv: role = 'mothership'
    elif 'counter_swarm.runtime:configured_ingress' in argv: role = 'ingress'
    elif 'counter_swarm.runtime:configured_proxy' in argv:
        role = 'edge'
        assert observed == ['gate', 'health'], observed
    elif argv[-1] == 'work': role = 'worker'
    else: raise AssertionError('Unexpected child command')
    assert kwargs.get('env') is not None, role
    output = workspace / (role + '.json')
    child = real_popen([sys.executable, str(workspace/'probe.py'), str(output), role],
                       **kwargs, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    children.append(child); roles.append(role)
    deadline = time.monotonic() + 5
    while not output.exists():
        if child.poll() is not None or time.monotonic() > deadline:
            raise AssertionError('Inert child failed to report')
        time.sleep(.01)
    if scenario == 'child_exit' and role == 'deadbolt':
        child.terminate(); child.wait(timeout=5)
    if role == 'worker': handlers[signal.SIGTERM]()
    return child
supervisor.subprocess = SimpleNamespace(Popen=launch, TimeoutExpired=subprocess.TimeoutExpired)
error = None
try:
    supervisor.main()
except RuntimeError as exc:
    error = str(exc)
finally:
    for child in children:
        if child.poll() is None: child.kill()
        child.wait(timeout=5)
assert all(child.poll() is not None for child in children)
print(json.dumps({'roles': roles, 'error': error, 'observed': observed,
                  'all_children_stopped': True}))
"""


def run_supervisor(tmp_path, scenario):
    (tmp_path / "probe.py").write_text(textwrap.dedent(PROBE))
    driver = tmp_path / "driver.py"
    driver.write_text(textwrap.dedent(DRIVER))
    # Explicit fictional environment only; the test process retains its own state.
    env = {name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ}
    env.update(PATH=str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", ""),
        TMPDIR=str(tmp_path), LANG="C", LC_CTYPE="C", PORT="8080",
        DEADBOLT_TOKEN="fictional-sidecar-token", MS_DEADBOLT_REQUIRED="true",
        MS_MASTER_KEY="fictional-master", MS_BOOTSTRAP_OWNER_KEY="fictional-owner",
        MS_DATA_DIR="fictional-data", MS_DATABASE_URL="fictional-db-url",
        MS_PRODUCT_BINDINGS_FILE="fictional-product-bindings", MS_ENV="prod",
        MS_SMTP_ENABLED="false", MS_SCHEDULER_ENABLED="false",
        OPENAI_API_KEY="fictional-provider", CUSTOM_AUTH="fictional-custom-provider",
        STRIPE_SECRET_KEY="fictional-unrelated", COUNTER_SWARM_UNEXPECTED_SECRET="fictional",
        COUNTER_SWARM_CONTROL_BINDING="fictional-control-binding",
        COUNTER_SWARM_RUNTIME_CONFIG="fictional-runtime-config",
        COUNTER_SWARM_MOTHERSHIP_AGENT_ID="fictional-controller",
        COUNTER_SWARM_MODEL="fictional-model", COUNTER_SWARM_MAX_MODEL_CALLS="1",
        COUNTER_SWARM_MODEL_BUDGET_FILE="fictional-budget",
        PYTHONPATH="/fictional-untrusted-import-root", PYTHONINSPECT="1",
        HTTP_PROXY="http://untrusted.invalid", SSL_CERT_FILE="/fictional-untrusted-ca")
    # These hooks are deliberately present only in the driver; no installed code
    # is sourced from them. A bogus PYTHONHOME would prevent the driver starting.
    result = subprocess.run([sys.executable, str(driver), str(ROOT), str(tmp_path), scenario],
        env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout), {path.stem: json.loads(path.read_text())
        for path in tmp_path.glob("*.json")}


def test_actual_children_receive_only_role_grants_and_keep_runtime(tmp_path):
    result, reports = run_supervisor(tmp_path, "healthy")
    assert result["roles"] == ["deadbolt", "mothership", "ingress", "edge", "worker"]
    assert result["error"] is None and result["all_children_stopped"]
    assert set(reports) == ROLES
    for role, report in reports.items():
        names = set(report["names"])
        assert report["temp_ok"] and report["path_ok"] and report["lang_ok"] and report["ctype_ok"]
        assert not names & {"CUSTOM_AUTH", "STRIPE_SECRET_KEY", "COUNTER_SWARM_UNEXPECTED_SECRET",
                            "PYTHONPATH", "PYTHONINSPECT", "HTTP_PROXY", "SSL_CERT_FILE", "PORT"}
        assert ("OPENAI_API_KEY" in names) == (role == "mothership")
        assert ("MS_MASTER_KEY" in names) == (role == "mothership")
        assert ("MS_BOOTSTRAP_OWNER_KEY" in names) == (role == "mothership")
        assert ("COUNTER_SWARM_CONTROL_BINDING" in names) == (role == "mothership")
        assert ("COUNTER_SWARM_RUNTIME_CONFIG" in names) == (role in {"edge", "ingress", "worker"})
        assert ("DEADBOLT_TOKEN" in names) == (role == "deadbolt")
        assert ("DEADBOLT_DB" in names) == (role == "deadbolt")
        assert ("DEADBOLT_EVENTS" in names) == (role == "deadbolt")
        assert report["readiness_marker"] == ("true" if role == "mothership" else None)


@pytest.mark.parametrize("scenario", ["gate_down", "child_exit"])
def test_actual_spawn_cleanup_keeps_edge_closed_on_prerequisite_failure(tmp_path, scenario):
    result, reports = run_supervisor(tmp_path, scenario)
    assert result["roles"] == ["deadbolt", "mothership", "ingress"]
    assert "edge" not in reports and "worker" not in reports
    assert result["error"] and result["all_children_stopped"]
