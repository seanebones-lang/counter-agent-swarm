#!/usr/bin/env python3
"""Standard-library-only client for a supervised private native integration lab."""
import argparse
import json
from pathlib import Path
import stat
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default="http://127.0.0.1:18765")
    p.add_argument("--token-file", type=Path, required=True)
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    start = commands.add_parser("start")
    start.add_argument("scenario", choices=["kill", "deny", "revoke", "reject_approval", "restart_pending", "unavailable"])
    for name in ["status", "step", "cancel", "operator-status", "operator-approve", "operator-reject"]:
        cmd = commands.add_parser(name)
        cmd.add_argument("run_id", type=UUID)
        if name in {"step", "operator-approve", "operator-reject"}:
            cmd.add_argument("revision", type=int)
    args = p.parse_args()
    target = urllib.parse.urlsplit(args.url)
    if (target.scheme not in {"http", "https"} or target.username or target.password or
            target.path not in {"", "/"} or target.query or target.fragment or
            (target.scheme == "http" and target.hostname not in {"127.0.0.1", "::1"})):
        p.error("Use a literal loopback HTTP tunnel or operator-provided HTTPS origin")
    info = args.token_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        p.error("Token must be an owner-only regular file, not a symlink")
    token = args.token_file.read_text().strip()
    if len(token) < 32 or len(token) > 512:
        p.error("Invalid session token file")
    command = args.command
    data = None
    method = "GET"
    if command == "plan":
        path = "/plan"
    elif command == "start":
        path, method, data = "/runs", "POST", {"scenario": args.scenario}
    else:
        path = ("/operator/runs/" if command.startswith("operator-") else "/runs/") + str(args.run_id)
        if command in {"step", "cancel", "operator-approve", "operator-reject"}:
            method = "POST"
            if command.startswith("operator-"):
                path += "/approval"
                data = {"revision": args.revision, "approve": command == "operator-approve"}
            else:
                path += "/" + command
                data = {} if command == "cancel" else {"revision": args.revision}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(args.url.rstrip("/") + path,
        data=None if data is None else json.dumps(data).encode(), method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=10) as reply:
            content = reply.read(131073)
            if len(content) > 131072:
                p.exit(1, "Response exceeds budget\n")
            print(json.dumps(json.loads(content), indent=2))
    except urllib.error.HTTPError as error:
        print(json.dumps({"http_status": error.code, "detail": error.read(2048).decode(errors="replace")}))
        raise SystemExit(1)
    except (OSError, ValueError):
        p.exit(1, "Lab unavailable or response invalid; check status with the operator\n")


if __name__ == "__main__":
    main()
