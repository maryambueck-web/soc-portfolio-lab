"""Integration checks in a temporary isolated copy. Standard library only."""
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
    root = Path(d)/'lab'
    shutil.copytree(source, root, ignore=shutil.ignore_patterns('reports','data','__pycache__','.venv','.git'))
    def run(*args):
        return subprocess.run([sys.executable, 'pipeline.py', *args], cwd=root, capture_output=True, text=True, timeout=120)
    first = run()
    assert first.returncode == 0, first.stderr
    latest = json.loads((root/'reports/latest.json').read_text())
    folder = root/'reports/runs'/latest['run_id']
    events = [json.loads(l) for l in (folder/'events.jsonl').read_text().splitlines()]
    for e in events:
        e.pop('scenario'); e.pop('malicious')
    external = root/'external.jsonl'
    external.write_text(''.join(json.dumps(e)+'\n' for e in events))
    assert run('--input', str(external)).returncode == 0
    pointer = (root/'reports/latest.json').read_bytes()
    last_id = json.loads(pointer)['run_id']
    metrics = json.loads((root/'reports/runs'/last_id/'metrics.json').read_text())
    assert metrics['baseline']['status'] == 'not_available'
    external.write_text('{broken}\n')
    assert run('--input', str(external)).returncode == 1
    assert (root/'reports/latest.json').read_bytes() == pointer
    with (root/'reports/.pipeline.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert run().returncode == 2
    assert (root/'reports/latest.json').read_bytes() == pointer
print('Pipeline demo/import/no false metrics/failed batch/overlap lock: PASS')
