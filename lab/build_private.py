#!/usr/bin/env python3
"""Stage an operator-private image context from explicit reviewed artifacts.

No provider credentials, .env, repositories or home directories enter the image.
Mothership stays an external unmodified dependency. Never distribute this image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mothership-source", type=Path, required=True)
    p.add_argument("--deadbolt-archive", type=Path, required=True)
    p.add_argument("--checksums", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--host-description", required=True)
    a = p.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = a.out.resolve()
    engine = a.mothership_source.resolve()
    if output.is_relative_to(source) or output.is_relative_to(engine):
        p.error("Private build output must be outside both repositories")
    def git(root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    if git(engine, "status", "--porcelain", "--untracked-files=no"):
        p.error("Mothership tracked source must be clean")
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    expected = [line.split()[0] for line in a.checksums.read_text().splitlines()
                if line.split()[-1].lstrip("*") == a.deadbolt_archive.name]
    if len(expected) != 1 or sha(a.deadbolt_archive) != expected[0]:
        p.error("DeadBolt archive does not match the reviewed release checksum")
    os.umask(0o077)
    if a.out.is_symlink():
        p.error("Private build output must not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    import stat
    info=output.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
        p.error("Private build output must be an owner-only directory")
    deps = output/"dependency-artifacts"
    deps.mkdir(mode=0o700,exist_ok=True)
    import sys
    subprocess.run([sys.executable,"-m","build","--wheel","--outdir",str(deps)],
                   cwd=engine,check=True)
    wheels=list(deps.glob('n11_mothership-0.3.0-*.whl'))
    if len(wheels)!=1:
        p.error("Expected exactly one reviewed Mothership 0.3.0 wheel")
    wheel=wheels[0]
    with zipfile.ZipFile(wheel) as z:
        if any(Path(n).name.startswith('.env') or n.endswith(('.sqlite','.key','.pem')) for n in z.namelist()):
            p.error("Unexpected private state in engine wheel")
    with zipfile.ZipFile(a.deadbolt_archive) as z:
        members=[n for n in z.namelist() if Path(n).name=='deadbolt']
        if len(members)!=1:
            p.error("Expected exactly one native executable")
        (deps/'deadbolt').write_bytes(z.read(members[0]))
        (deps/'deadbolt').chmod(0o755)
    files=[source/n for n in ['pyproject.toml','LICENSE','NOTICE','README.md',
        'scripts/acceptance.py','scripts/linux_lab_server.py','scripts/linux_lab_client.py',
        'scripts/test_glue_only.py','scripts/collect_component_results.py',
        'lab/Dockerfile','lab/Dockerfile.dockerignore']]
    for folder,pattern in [('src/counter_swarm','*.py'),('tests','*.py'),('examples','*.json')]:
        files.extend(sorted((source/folder).glob(pattern)))
    hashes={}
    for file in files:
        relative=file.relative_to(source)
        target=output/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(file,target)
        hashes[str(relative)]=sha(file)
    manifest={'schema_version':1,'scope':'operator-hosted real native engines with fixture analyst',
        'glue_base_revision':git(source,'rev-parse','HEAD'), 'public_file_sha256':hashes,
        'mothership_version':'0.3.0','mothership_source_revision':git(engine,'rev-parse','HEAD'),
        'mothership_wheel_sha256':sha(wheel),'deadbolt_version':'2.0.0',
        'deadbolt_release_archive_sha256':sha(a.deadbolt_archive),
        'deadbolt_binary_sha256':sha(deps/'deadbolt'),'host':a.host_description,
        'provider_keys_in_image':False,'live_model_calls':0,'exploit_detonation':False}
    (output/'lab-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if git(engine,'status','--porcelain','--untracked-files=no'):
        p.error('Mothership source changed during build')
    print('Private build context staged. Build with lab/Dockerfile; never upload or distribute it.')


if __name__=='__main__':
    main()
