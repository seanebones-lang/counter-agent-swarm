"""Lab access boundaries with inert runners; real engines are tested separately."""
import importlib.util
from pathlib import Path
import sys
import time

from fastapi.testclient import TestClient
import pytest

spec = importlib.util.spec_from_file_location("linux_lab_server", Path(__file__).parents[1] / "scripts/linux_lab_server.py")
lab_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lab_module
spec.loader.exec_module(lab_module)

TESTER = {"Authorization": "Bearer " + "t" * 48}
OPERATOR = {"Authorization": "Bearer " + "o" * 48}


def fixture_runner(binary, *, scenario, observer):
    observer("ready", {"action": "kill"})
    observer("healthy", {"http_status": 200, "upstream_requests": 1})
    observer("detected", {"http_status": 403, "upstream_requests": 1})
    approved = observer("approval_pending", {"target_still_admitted": True})
    return {"status": "fixture_only", "approved": approved}


def make_lab(**kwargs):
    return lab_module.Lab("not-a-real-binary", "t" * 48, "o" * 48, {"fixture_only": True},
                          runner=fixture_runner, step_timeout=1, **kwargs)


def poll(client, path, phase):
    for _ in range(100):
        value = client.get(path, headers=TESTER).json()
        if value["phase"] == phase:
            return value
        time.sleep(.01)
    raise AssertionError(value)


def test_roles_closed_routes_and_bounded_input():
    with TestClient(lab_module.create_app(make_lab())) as c:
        assert c.get("/plan").status_code == 403
        assert c.get("/plan", headers=OPERATOR).status_code == 403
        assert c.get("/docs", headers=TESTER).status_code == 404
        assert c.get("/plan", headers={**TESTER, "Origin": "https://untrusted.invalid"}).status_code == 403
        assert c.post("/runs", headers=TESTER, content=b"x"*2049).status_code == 413
        assert c.post("/runs", headers=TESTER, json={"scenario": "shell"}).status_code == 422
        assert c.post("/runs", headers=TESTER, json={"scenario": "kill", "target": "/private"}).status_code == 422
        assert c.get("/runs/not-a-uuid", headers=TESTER).status_code == 422
        assert c.get("/plan", headers=TESTER).json()["private_runtime_download"] is False


@pytest.mark.parametrize("scenario,approve", [("kill", True), ("reject_approval", False)])
def test_tester_can_step_but_only_operator_can_decide(scenario, approve):
    lab = make_lab()
    with TestClient(lab_module.create_app(lab)) as c:
        value = c.post("/runs", headers=TESTER, json={"scenario": scenario}).json()
        path = "/runs/" + value["run_id"]
        assert c.post("/runs", headers=TESTER, json={"scenario": "deny"}).status_code == 409
        for phase in ["ready", "healthy", "detected"]:
            state = poll(c, path, phase)
            assert c.post(path+"/step", headers=TESTER, json={"revision": state["revision"]-1}).status_code == 409
            assert c.post(path+"/step", headers=TESTER, json={"revision": state["revision"]}).status_code == 200
        state = poll(c, path, "approval_pending")
        assert c.post(path+"/step", headers=TESTER, json={"revision": state["revision"]}).status_code == 409
        owner_path = "/operator"+path+"/approval"
        decision = {"revision": state["revision"], "approve": approve}
        assert c.post(owner_path, headers=TESTER, json=decision).status_code == 403
        assert c.post(owner_path, headers=OPERATOR, json={**decision, "approve": not approve}).status_code == 409
        assert c.post(owner_path, headers=OPERATOR, json=decision).status_code == 200
        assert c.post(owner_path, headers=OPERATOR, json=decision).status_code == 409
        assert poll(c, path, "passed")["receipt"]["approved"] is approve


def test_cancellation_run_budget_and_expiry():
    lab = make_lab(run_limit=1)
    with TestClient(lab_module.create_app(lab)) as c:
        value = c.post("/runs", headers=TESTER, json={"scenario": "kill"}).json()
        path = "/runs/"+value["run_id"]
        poll(c, path, "ready")
        assert c.post(path+"/cancel", headers=TESTER, json={}).status_code == 200
        poll(c, path, "cancelled")
        assert c.post("/runs", headers=TESTER, json={"scenario": "kill"}).status_code == 429
        lab.deadline = 0
        assert c.get("/plan", headers=TESTER).status_code == 410
    assert not any(t.is_alive() for t in lab.threads)


@pytest.mark.parametrize("broken_log", [False, True])
def test_exception_details_and_private_paths_not_disclosed(tmp_path, broken_log):
    def bad(*args, **kwargs):
        raise RuntimeError("SECRET /private/runtime/source.py")
    lab = make_lab()
    lab.runner = bad
    lab.error_log = tmp_path if broken_log else None
    with TestClient(lab_module.create_app(lab)) as c:
        value = c.post("/runs", headers=TESTER, json={"scenario": "kill"}).json()
        path = "/runs/"+value["run_id"]
        result = poll(c, path, "failed")
        assert "SECRET" not in str(result) and "/private/runtime" not in str(result)


def test_shared_or_short_credentials_refused():
    with pytest.raises(ValueError):
        lab_module.Lab("binary", "same"*12, "same"*12, {})
    with pytest.raises(ValueError):
        lab_module.Lab("binary", "short", "o"*48, {})
