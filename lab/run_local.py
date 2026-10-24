#!/usr/bin/env python3
"""Operate only the labelled disposable local lab, using an explicit Docker context."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess

LABEL = "dev.nexteleven.swarm-native-lab"
NAME = "n11-swarm-native-lab"
NETWORK = NAME + "-isolated"
VOLUME = NAME + "-credentials"
BASE = "python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["start", "stop", "status"])
    p.add_argument("--context", required=True)
    p.add_argument("--image", default="nexteleven/swarm-native-lab:20261024")
    p.add_argument("--private-dir", type=Path, required=True)
    p.add_argument("--vm-ssh-config", type=Path)
    p.add_argument("--vm-ssh-host", default="lima-colima-swarm-lab")
    a = p.parse_args()
    docker = ["docker", "--context", a.context]
    def call(*args, data=None, check=True):
        return subprocess.run([*docker, *args], input=data, capture_output=True,
                              check=check, timeout=120).stdout
    def owned(kind, name):
        result = subprocess.run([*docker, kind, "inspect", name], capture_output=True, timeout=10)
        if result.returncode:
            return False
        value = json.loads(result.stdout)[0]
        labels = value.get("Labels", {}) if kind != "container" else value.get("Config", {}).get("Labels", {})
        if labels.get(LABEL) != "disposable":
            p.error("Refusing an unlabelled or unrelated Docker resource: " + name)
        return True
    if a.command == "status":
        print(call("ps", "--filter", "label="+LABEL, "--format", "{{.Names}} {{.Status}} {{.Ports}}").decode())
        return
    if a.command == "stop":
        socket = a.private_dir/"forward.sock"
        if socket.exists():
            subprocess.run(["ssh", "-S", str(socket), "-O", "exit", a.vm_ssh_host],
                           capture_output=True, timeout=10, check=True)
        if owned("container", NAME):
            call("stop", "--time", "40", NAME)
            call("rm", NAME)
        if owned("volume", VOLUME):
            call("volume", "rm", VOLUME)
        if owned("network", NETWORK):
            call("network", "rm", NETWORK)
        for filename in ["tester.key", "operator.key"]:
            (a.private_dir / filename).unlink(missing_ok=True)
        print("Disposable container, network and session credentials removed; private image retained.")
        return
    if a.vm_ssh_config is None or not a.vm_ssh_config.is_file():
        p.error("This isolated-network profile requires the operator's local VM SSH config")
    for kind, name in [("container", NAME), ("volume", VOLUME), ("network", NETWORK)]:
        if owned(kind, name):
            p.error("A prior lab exists; inspect it and stop it before starting a fresh session")
    os.umask(0o077)
    a.private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = a.private_dir.lstat()
    import stat
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        p.error("Private directory must be an owner-only directory, not a symlink")
    credentials = {role: secrets.token_urlsafe(36) for role in ["tester", "operator"]}
    for role, token in credentials.items():
        fd = os.open(a.private_dir / (role+".key"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(token+"\n")
    try:
        call("network", "create", "--internal", "--label", LABEL+"=disposable", NETWORK)
        call("volume", "create", "--label", LABEL+"=disposable", VOLUME)
        setup = ("import os,sys,pathlib; os.umask(0o077); p=pathlib.Path('/run/lab'); "
                 "os.chmod(p,0o700); f=p/'credentials.json'; f.write_bytes(sys.stdin.buffer.read(4096)); "
                 "os.chmod(f,0o600); os.chown(f,10001,10001); os.chown(p,10001,10001)")
        call("run", "--rm", "--platform", "linux/amd64", "--network", "none", "-i",
             "--mount", "type=volume,source="+VOLUME+",target=/run/lab", BASE,
             "python", "-c", setup, data=json.dumps(credentials).encode())
        call("run", "-d", "--init", "--name", NAME, "--label", LABEL+"=disposable",
             "--platform", "linux/amd64", "--network", NETWORK,
             "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges=true", "--pids-limit", "192",
             "--memory", "2g", "--cpus", "2", "--tmpfs", "/tmp:rw,nosuid,nodev,size=384m",
             "--mount", "type=volume,source="+VOLUME+",target=/run/lab,readonly", a.image)
        detail = json.loads(call("inspect", NAME))[0]
        ip = detail["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
        subprocess.run(["ssh", "-F", str(a.vm_ssh_config), "-o", "ControlMaster=yes",
            "-o", "ControlPersist=no", "-S", str(a.private_dir/"forward.sock"),
            "-o", "ExitOnForwardFailure=yes", "-fNT", "-L", "127.0.0.1:18765:"+ip+":8765",
            a.vm_ssh_host], capture_output=True, check=True, timeout=15)
        import time
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic()+30
        while True:
            try:
                request=urllib.request.Request('http://127.0.0.1:18765/plan',
                    headers={'Authorization':'Bearer '+credentials['tester']})
                with opener.open(request, timeout=1) as response:
                    if response.status==200:
                        break
            except OSError:
                pass
            if time.monotonic()>=deadline:
                p.exit(1,'Lab did not become ready. Inspect and stop the disposable session.\n')
            time.sleep(.2)
    except subprocess.SubprocessError:
        p.exit(1, "Startup failed. Inspect the labelled lab, then run stop; never reuse these credentials.\n")
    print("Lab started on http://127.0.0.1:18765; session lifetime 30 minutes.")
    print("Tester and operator credentials are separate owner-only files in the private directory.")
    print("Never send the image, operator key, Docker socket or private directory to the tester.")


if __name__ == "__main__":
    main()
