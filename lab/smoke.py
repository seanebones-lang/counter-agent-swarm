#!/usr/bin/env python3
"""Operator-only two-role automation. Never include operator keys in a tester kit."""
import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default="http://127.0.0.1:18765")
    p.add_argument("--operator-url", default="http://127.0.0.1:18765")
    p.add_argument("--scenario", choices=["kill", "deny", "revoke", "reject_approval", "restart_pending", "unavailable"])
    p.add_argument("--private-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    origin=urlsplit(a.url)
    operator_origin=urlsplit(a.operator_url)
    if (origin.scheme not in {'http','https'} or origin.username or origin.password or
        origin.path not in {'','/'} or origin.query or origin.fragment or
        (origin.scheme=='http' and origin.hostname not in {'127.0.0.1','::1'})):
        p.error('Use HTTPS or a literal loopback tester origin')
    if (operator_origin.scheme!='http' or operator_origin.hostname not in {'127.0.0.1','::1'} or
        operator_origin.username or operator_origin.password or operator_origin.path not in {'','/'} or
        operator_origin.query or operator_origin.fragment):
        p.error('Operator credential must stay on the literal loopback channel')
    tokens = {role: (a.private_dir/(role+".key")).read_text().strip() for role in ["tester", "operator"]}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def call(path, value=None, role="tester", expected=200):
        headers = {"Authorization": "Bearer "+tokens[role], "Content-Type": "application/json"} if role else {}
        origin = a.operator_url if role == "operator" else a.url
        request = urllib.request.Request(origin.rstrip("/")+path,
            data=None if value is None else json.dumps(value).encode(), headers=headers)
        try:
            with opener.open(request, timeout=10) as reply:
                status, content = reply.status, reply.read(131072)
        except urllib.error.HTTPError as error:
            status, content = error.code, error.read(2048)
        assert status == expected, (path, status, content[:300])
        return json.loads(content)
    assert call("/plan", role=None, expected=403)
    plan = call("/plan")
    receipts = []
    for scenario in ([a.scenario] if a.scenario else plan["scenarios"]):
        value = call("/runs", {"scenario": scenario}, expected=202)
        path = "/runs/"+value["run_id"]
        handled = set()
        deadline = time.monotonic()+240
        while time.monotonic()<deadline:
            value = call(path)
            phase = value["phase"]
            if phase == "passed":
                receipts.append(value)
                print(json.dumps({"scenario": scenario, "status": "passed"}), flush=True)
                break
            assert phase not in {"failed", "cancelled", "timed_out"}, value
            revision = value["revision"]
            if (phase,revision) not in handled:
                if phase in {"ready", "healthy", "detected"}:
                    call(path+"/step", {"revision": revision})
                    handled.add((phase,revision))
                elif phase == "approval_pending":
                    decision = {"revision": revision, "approve": scenario != "reject_approval"}
                    owner_path = "/operator"+path+"/approval"
                    call(owner_path, decision, expected=403)
                    call(owner_path, decision, role="operator")
                    call(owner_path, decision, role="operator", expected=409)
                    handled.add((phase,revision))
            time.sleep(.2)
        else:
            call(path+"/cancel", {})
            raise RuntimeError("Scenario deadline exceeded")
    output = {"status": "passed", "scope": "NextEleven-controlled native Linux integration through two-role HTTP lab",
              "independent_external_test": False, "plan": plan, "runs": receipts,
              "tester_could_not_approve": True, "duplicate_decision_refused": True,
              "live_model_calls": 0, "exploit_detonation": False}
    a.out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    a.out.write_text(json.dumps(output,indent=2)+"\n")
    a.out.chmod(0o600)
    print(str(len(receipts))+" native scenario(s) passed; private receipt saved.")


if __name__ == "__main__":
    main()
