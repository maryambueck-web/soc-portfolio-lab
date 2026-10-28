"""Bounded, strict JSON input and atomic private output; no command execution."""
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 20000

def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be text')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid ISO timestamp') from exc
    if result.utcoffset() is None:
        raise ValueError('timestamp requires timezone')
    return result.astimezone(timezone.utc)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def strict_json(text):
    def reject(value):
        raise ValueError('non-finite JSON number')
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject)

def validate(events):
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError('expected <=20000 events')
    ids = set()
    for e in events:
        if not isinstance(e, dict):
            raise ValueError('event must be object')
        for key in ('event_id', 'timestamp', 'device', 'user', 'kind'):
            if not isinstance(e.get(key), str) or not e[key].strip() or len(e[key]) > 256:
                raise ValueError('missing/invalid field: ' + key)
        if e['event_id'] in ids:
            raise ValueError('duplicate event_id')
        ids.add(e['event_id'])
        timestamp(e['timestamp'])
        if e['kind'] not in ('process', 'login', 'file_burst', 'shadow_delete'):
            raise ValueError('unsupported kind')
        if e['kind'] == 'process':
            for key in ('process', 'command'):
                if not isinstance(e.get(key), str) or not e[key] or len(e[key]) > 32768:
                    raise ValueError('invalid process field: ' + key)
            for key in ('script_path', 'script_sha256', 'parent'):
                if key in e and (not isinstance(e[key], str) or len(e[key]) > 32768):
                    raise ValueError('invalid optional process field')
        if e['kind'] == 'login':
            if e.get('outcome') not in ('success', 'failure'):
                raise ValueError('invalid login outcome')
            if not isinstance(e.get('src_ip'), str):
                raise ValueError('src_ip must be text')
            ipaddress.ip_address(e['src_ip'])
            if type(e.get('logon_type')) is not int or e['logon_type'] < 0:
                raise ValueError('invalid logon_type')
        if e['kind'] == 'file_burst':
            if type(e.get('changed_files')) is not int or not 0 <= e['changed_files'] <= 1000000000:
                raise ValueError('invalid changed_files')
        if 'malicious' in e and type(e['malicious']) is not bool:
            raise ValueError('malicious label must be boolean')
        if 'scenario' in e and (not isinstance(e['scenario'], str) or not e['scenario']):
            raise ValueError('invalid scenario label')
    return events

def load_events(path):
    # Bound bytes before decoding; invalid input fails the whole batch, never silently skips.
    with Path(path).open('rb') as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('input exceeds 10 MiB')
    events = []
    for number, line in enumerate(data.decode('utf-8').splitlines(), 1):
        if line.strip():
            try:
                events.append(strict_json(line))
            except ValueError as exc:
                raise ValueError(f'invalid JSON at line {number}') from exc
            if len(events) > MAX_EVENTS:
                raise ValueError('too many events')
    return validate(events)

def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError('refusing symlink output')
    fd, temp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def write_json(path, value):
    atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n')
