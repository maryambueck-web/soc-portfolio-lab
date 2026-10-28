"""Synthetic SOC lab. No network actions or endpoint commands are executed."""
import hashlib
import json
import ipaddress
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from safeio import timestamp, validate, write_json, atomic_text, strict_json

ROOT = Path(__file__).resolve().parent
APPROVED_HASH = hashlib.sha256(b'lab-approved-backup-script-v1').hexdigest()
RULE_VERSION = '3.0.0'
# Heuristic token match, not a complete Windows/PowerShell command-line parser.
ENCODED = re.compile(r'(?i)(?:^|\s)["\']?[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)["\']?(?:\s|:)')

def ts(value):
    return timestamp(value)

POLICY_PATH = ROOT / 'config' / 'backup_exception.json'

def load_policy():
    policy = strict_json(POLICY_PATH.read_text(encoding='utf-8'))
    required = {'id','owner','reason','expires_at','device','user','script_path','script_sha256'}
    if set(policy) != required or any(not isinstance(v, str) or not v.strip() for v in policy.values()):
        raise ValueError('invalid backup exception policy')
    if not re.fullmatch(r'[0-9a-f]{64}', policy['script_sha256']):
        raise ValueError('invalid exception hash')
    ts(policy['expires_at'])
    return policy

def generate():
    base = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = []
    def add(minutes, scenario, malicious, **kwargs):
        events.append(dict(event_id=f'E{len(events)+1:03}', timestamp=(base+timedelta(minutes=minutes)).isoformat(), scenario=scenario, malicious=malicious, **kwargs))
    # Strings only: these commands are never executed.
    add(1, 'PS-ATTACK', True, kind='process', device='LAB-PC01', user='user01', process='powershell.exe', parent='winword.exe', command='powershell.exe -EncodedCommand TEST_ONLY', script_path='', script_sha256='')
    add(2, 'PS-BACKUP', False, kind='process', device='LAB-BACKUP01', user='svc_backup', process='powershell.exe', parent='taskeng.exe', command='powershell.exe -enc TEST_ONLY', script_path='C:\\Lab\\approved-backup.ps1', script_sha256=APPROVED_HASH)
    add(3, 'PS-NORMAL', False, kind='process', device='LAB-PC02', user='admin01', process='pwsh.exe', parent='explorer.exe', command='pwsh.exe -Command Get-Date', script_path='', script_sha256='')
    for i in range(5):
        add(10+i*.5, 'AUTH-ATTACK', True, kind='login', device='LAB-SRV01', user='user02', src_ip='192.0.2.10', outcome='failure', logon_type=10)
    add(13, 'AUTH-ATTACK', True, kind='login', device='LAB-SRV01', user='user02', src_ip='192.0.2.10', outcome='success', logon_type=10)
    add(20, 'AUTH-TYPO', False, kind='login', device='LAB-PC02', user='user03', src_ip='192.0.2.20', outcome='failure', logon_type=2)
    add(21, 'AUTH-TYPO', False, kind='login', device='LAB-PC02', user='user03', src_ip='192.0.2.20', outcome='success', logon_type=2)
    add(30, 'FILE-ATTACK', True, kind='file_burst', device='LAB-FS01', user='user04', changed_files=800)
    add(31, 'FILE-ATTACK', True, kind='shadow_delete', device='LAB-FS01', user='user04')
    add(40, 'FILE-BACKUP', False, kind='file_burst', device='LAB-FS02', user='svc_backup', changed_files=900)
    return sorted(events, key=lambda e: ts(e['timestamp']))

def approved_backup(e, policy=None, now=None):
    policy = load_policy() if policy is None else policy
    now = datetime.now(timezone.utc) if now is None else now
    return (now < ts(policy['expires_at'])
            and ts(e['timestamp']) < ts(policy['expires_at'])
            and all(e.get(k) == policy[k] for k in ('device','user','script_path','script_sha256')))

def detect(events, tuned=False, *, suppressed=None, now=None):
    validate(events)
    policy = load_policy() if tuned else None
    now = datetime.now(timezone.utc) if now is None else now
    failures = defaultdict(deque)
    bursts = defaultdict(list)
    alerts = []
    def alert(rule, evidence, reason, priority):
        e = evidence[-1]
        identity = rule + ':' + ':'.join(x['event_id'] for x in evidence)
        alerts.append(dict(alert_id=hashlib.sha256(identity.encode()).hexdigest()[:24],
                           rule_version=RULE_VERSION, rule=rule, timestamp=e['timestamp'],
                           device=e['device'], user=e['user'], priority=priority,
                           reason=reason, evidence=[x['event_id'] for x in evidence]))
    for e in sorted(events, key=lambda x: (ts(x['timestamp']), x['event_id'])):
        if e['kind'] == 'process' and e['process'].lower() in ('powershell.exe','pwsh.exe') and ENCODED.search(e['command']):
            if tuned and approved_backup(e, policy, now):
                if suppressed is not None:
                    suppressed.append(dict(rule='PS-001', event_id=e['event_id'], exception_id=policy['id'],
                                           reason=policy['reason'], expires_at=policy['expires_at']))
            else:
                alert('PS-001', [e], 'Encoded PowerShell parameter; investigate context.', 'medium')
        if e['kind'] == 'login':
            # Logon types are different authentication contexts; do not merge them.
            key = (e['device'],e['user'],str(ipaddress.ip_address(e['src_ip'])),e['logon_type'])
            current = ts(e['timestamp'])
            queue = failures[key]
            while queue and current - queue[0][0] > timedelta(minutes=5):
                queue.popleft()
            if e['outcome'] == 'failure':
                queue.append((current, e))
            elif e['outcome'] == 'success':
                relevant = [f for stamp, f in queue if stamp < current]
                if len(relevant) >= 5:
                    alert('AUTH-001', relevant+[e], 'Success after >=5 earlier failures within inclusive 5-minute window; same host/user/IP/logon type.', 'high')
                queue.clear()
        if e['kind'] == 'file_burst' and e['changed_files'] >= 500:
            bursts[e['device']].append(e)
        if e['kind'] == 'shadow_delete':
            # Strictly later: equal timestamps do not prove a sequence.
            candidates = [b for b in bursts[e['device']] if timedelta(0) < ts(e['timestamp'])-ts(b['timestamp']) <= timedelta(minutes=2)]
            if candidates:
                alert('FILE-001', [candidates[-1],e], '>=500 changes followed by shadow deletion on same host within 2 minutes; host correlation, no causal proof.', 'critical')
    return alerts

def evaluate(events, alerts):
    # Ground-truth labels are used only here, never as detection inputs.
    by_id={e['event_id']:e for e in events}
    truth = {}
    for e in events:
        if 'scenario' not in e or 'malicious' not in e:
            raise ValueError('metrics require complete ground-truth labels')
        if e['scenario'] in truth and truth[e['scenario']] != e['malicious']:
            raise ValueError('conflicting scenario labels')
        truth[e['scenario']] = e['malicious']
    found={by_id[eid]['scenario'] for a in alerts for eid in a['evidence']}
    tp=sum(label and name in found for name,label in truth.items())
    fp=sum(not label and name in found for name,label in truth.items())
    fn=sum(label and name not in found for name,label in truth.items())
    tn=sum(not label and name not in found for name,label in truth.items())
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=tp/(tp+fp) if tp+fp else None, recall=tp/(tp+fn) if tp+fn else None)

def create_reports(events, directory, now=None):
    validate(events)
    directory = Path(directory)
    suppressed = []
    report = {}
    for name, tuned in [('baseline', False), ('tuned', True)]:
        alerts = detect(events, tuned, suppressed=suppressed, now=now)
        write_json(directory / f'alerts_{name}.json', alerts)
        if events and all('scenario' in e and 'malicious' in e for e in events):
            report[name] = evaluate(events, alerts)
        else:
            report[name] = {'status': 'not_available', 'reason': 'No complete ground truth; no accuracy claim.'}
    write_json(directory / 'suppressed.json', suppressed)
    write_json(directory / 'metrics.json', report)
    return report

def run():
    events = generate()
    atomic_text(ROOT / 'data/events.jsonl', ''.join(json.dumps(e)+'\n' for e in events))
    print(json.dumps(create_reports(events, ROOT / 'reports'), indent=2))
    print('Synthetic data and reports created. No endpoint actions performed.')

if __name__ == '__main__':
    run()
