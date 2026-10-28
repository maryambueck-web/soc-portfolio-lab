"""Offline batch automation: test -> validate -> detect -> publish complete run."""
import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from lab import ROOT, RULE_VERSION, create_reports, generate, load_policy, ts
from safeio import atomic_text, load_events, write_json

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, help='Validated normalized JSONL; omitted = synthetic demo')
    args = parser.parse_args()
    os.umask(0o077)
    reports = ROOT / 'reports'
    reports.mkdir(exist_ok=True, mode=0o700)
    # Kernel releases lock even after interruption; macOS/Linux only.
    with (reports / '.pipeline.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another run is active.', file=sys.stderr)
            return 2
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                                cwd=ROOT, capture_output=True, text=True, timeout=120)
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr)
            return result.returncode
        events = load_events(args.input) if args.input else generate()
        now = datetime.now(timezone.utc)
        run_id = now.strftime('%Y%m%dT%H%M%S%fZ') + '-' + uuid.uuid4().hex[:8]
        target = reports / 'runs' / run_id
        target.mkdir(parents=True, mode=0o700)
        atomic_text(target / 'tests.txt', result.stdout + result.stderr)
        atomic_text(target / 'events.jsonl', ''.join(json.dumps(e, sort_keys=True)+'\n' for e in events))
        metrics = create_reports(events, target, now)
        policy = load_policy()
        write_json(target / 'exception_policy.json', policy)
        files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir() if p.is_file()}
        sources = {}
        for name in ('lab.py', 'safeio.py', 'pipeline.py', 'app.py', 'requirements.txt',
                     'tests/test_lab.py', 'tests/test_security.py', '.streamlit/config.toml'):
            sources[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        manifest = dict(run_id=run_id, created_at=now.isoformat(), rule_version=RULE_VERSION,
                        input_type='normalized_external' if args.input else 'synthetic',
                        event_count=len(events), exception_active=now < ts(policy['expires_at']),
                        python=sys.version, files_sha256=files, source_sha256=sources,
                        metrics=metrics)
        write_json(target / 'manifest.json', manifest)
        # Only finished runs become visible; failed runs never replace the last good run.
        write_json(reports / 'latest.json', {'run_id': run_id})
        print(json.dumps(manifest, indent=2))
        if not manifest['exception_active']:
            print('Backup exception expired; no matching alerts were suppressed.', file=sys.stderr)
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'Pipeline failed ({type(exc).__name__}); check input/config and file permissions. Latest run unchanged.', file=sys.stderr)
        raise SystemExit(1)
