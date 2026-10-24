#!/usr/bin/env python3
"""Create a public-client-only handoff from an explicit file allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    files={'client.py':(root/'scripts/linux_lab_client.py').read_bytes(),
           'README.txt':(root/'lab/TESTER_README.txt').read_bytes(),
           'LICENSE':(root/'LICENSE').read_bytes(),'NOTICE':(root/'NOTICE').read_bytes(),
           'FEEDBACK.txt':b'Name/alias:\nDate:\nClient OS/Python:\nLab manifest/version:\nScenarios attempted:\nExpected vs observed:\nFirst failed command/status:\nInstructions unclear:\nRedactions made:\nSuggestions:\n'}
    manifest={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
    files['FILES-SHA256.json']=json.dumps(manifest,indent=2).encode()+b'\n'
    a.out.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(a.out,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for name,data in files.items():
            z.writestr(name,data)
    print(json.dumps({'archive':str(a.out),'sha256':hashlib.sha256(a.out.read_bytes()).hexdigest(),
                      'members':list(files),'private_engines_or_credentials_included':False}))


if __name__=='__main__':
    main()
