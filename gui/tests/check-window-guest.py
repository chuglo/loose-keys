#!/usr/bin/env python3
"""Offline wrapper controls: no VM or UI starts; run from the repository root."""
import os, pathlib, subprocess, tempfile
with tempfile.TemporaryDirectory(prefix='window-deadline-',dir=os.environ.get('TMPDIR')) as td:
    root=pathlib.Path(td); fake=root/'tart'
    fake.write_text('''#!/usr/bin/env python3
import hashlib, os, pathlib, sys, time
args=sys.argv[1:]
with open(os.environ['RECORD'],'a') as f: f.write(' '.join(args)+'\\n')
if args[0]=='list': print('OCI ghcr.io/cirruslabs/macos-tahoe-base:latest 50 33 today stopped')
elif args[0]=='run': time.sleep(120)
elif args[0]=='exec':
    if args[2]=='shasum':
        archive=next(pathlib.Path(os.environ['OUT']).glob('run.*/share/source.tar'))
        print(hashlib.sha256(archive.read_bytes()).hexdigest()+'  source.tar',flush=True)
        if os.environ['MODE']=='stall': time.sleep(120)
    elif args[2]=='sh' and args[4].startswith('mkdir'): sys.exit(0 if os.environ['MODE']=='stall' else int(os.environ['MODE']))
    elif args[2]=='sh': print('fake report')
''')
    fake.chmod(0o700)
    for mode, expected in [('stall',1),('0',0),('7',7)]:
        out=root/('out-'+mode); record=root/('calls-'+mode)
        env=dict(os.environ,PATH=str(root)+':'+os.environ['PATH'],RECORD=str(record),MODE=mode,OUT=str(out))
        result=subprocess.run(['sh','gui/tests/check-window-guest.sh',str(out)],env=env,capture_output=True,text=True,timeout=55)
        assert result.returncode==expected,(mode,result.returncode,result.stdout,result.stderr)
        calls=record.read_text().splitlines()
        clone=next(line.split()[-1] for line in calls if line.startswith('clone '))
        assert 'stop '+clone in calls,calls
        assert not any(line.startswith('delete ') for line in calls)
        if mode=='stall': assert 'Infrastructure command exceeded 30s' in result.stderr,result.stderr
        print('PASS:',mode,'exit',expected,'and owned-clone cleanup',flush=True)
