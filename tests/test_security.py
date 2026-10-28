import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from lab import generate, detect, load_policy, ts, evaluate
from safeio import validate, load_events, atomic_text, strict_json

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)

def fixture(name):
    return copy.deepcopy([e for e in generate() if e['scenario'] == name])

class SecurityTests(unittest.TestCase):
    def test_expired_exception_is_not_applied_even_for_old_events(self):
        self.assertEqual(len(detect(fixture('PS-BACKUP'), True, now=ts(load_policy()['expires_at']) + timedelta(seconds=1))), 1)

    def test_expiry_boundary_is_exclusive(self):
        self.assertEqual(len(detect(fixture('PS-BACKUP'), True, now=ts(load_policy()['expires_at']))), 1)

    def test_suppression_is_audited(self):
        audit = []
        self.assertEqual(detect(fixture('PS-BACKUP'), True, now=NOW, suppressed=audit), [])
        self.assertEqual(audit[0]['event_id'], fixture('PS-BACKUP')[0]['event_id'])
        self.assertEqual(audit[0]['exception_id'], 'EX-LAB-001')

    def test_powershell_parameter_variants(self):
        e = fixture('PS-ATTACK')[0]
        for command in ('powershell.exe -e TEST', 'powershell.exe -ENC TEST', 'powershell.exe "-EncodedCommand" TEST', 'powershell.exe -enc:TEST'):
            with self.subTest(command=command):
                e['command'] = command
                self.assertEqual(len(detect([e])), 1)
        for command in ('powershell.exe -encoding UTF8', 'powershell.exe -Command Get-Date', 'powershell.exe C:\\scripts\\-enc.ps1'):
            with self.subTest(command=command):
                e['command'] = command
                self.assertEqual(detect([e]), [])

    def test_other_process_does_not_match(self):
        e = fixture('PS-ATTACK')[0]; e['process'] = 'example.exe'
        self.assertEqual(detect([e]), [])

    def test_auth_threshold_and_time_boundary(self):
        events = fixture('AUTH-ATTACK')
        for f in events[:-1]:
            f['timestamp'] = '2026-01-01T10:08:00Z'
        self.assertEqual(len(detect(events)), 1)  # exactly 5 minutes
        for f in events[:-1]:
            f['timestamp'] = '2026-01-01T10:07:59.999999Z'
        self.assertEqual(detect(events), [])
        self.assertEqual(detect(fixture('AUTH-ATTACK')[1:]), [])  # only four failures

    def test_auth_context_separation(self):
        for field, value in [('device','OTHER'), ('user','other'), ('logon_type',3)]:
            events = fixture('AUTH-ATTACK'); events[-1][field] = value
            with self.subTest(field=field):
                self.assertEqual(detect(events), [])

    def test_ipv6_normalized_for_correlation(self):
        events = fixture('AUTH-ATTACK')
        for e in events: e['src_ip'] = '2001:db8::1'
        events[-1]['src_ip'] = '2001:0db8:0000:0000:0000:0000:0000:0001'
        self.assertEqual(len(detect(events)), 1)

    def test_success_consumes_failure_sequence(self):
        events = fixture('AUTH-ATTACK')
        extra = dict(events[-1], event_id='E999', timestamp='2026-01-01T10:13:01Z')
        self.assertEqual(len(detect(events+[extra])), 1)

    def test_equal_times_do_not_prove_order(self):
        for name in ('AUTH-ATTACK', 'FILE-ATTACK'):
            events = fixture(name)
            for e in events: e['timestamp'] = '2026-01-01T10:00:00Z'
            self.assertEqual(detect(events), [])

    def test_file_boundaries_and_order(self):
        events = fixture('FILE-ATTACK')
        events[0]['changed_files'] = 500
        events[-1]['timestamp'] = '2026-01-01T10:32:00Z'
        self.assertEqual(len(detect(events)), 1)
        events[0]['changed_files'] = 499
        self.assertEqual(detect(events), [])
        events = fixture('FILE-ATTACK'); events[-1]['timestamp'] = '2026-01-01T10:29:59Z'
        self.assertEqual(detect(events), [])

    def test_alert_ids_stable_and_unique(self):
        alerts = detect(generate())
        self.assertEqual(len({a['alert_id'] for a in alerts}), len(alerts))
        self.assertEqual(alerts, detect(list(reversed(generate()))))

    def test_malformed_fields_rejected(self):
        cases = [('timestamp','2026-01-01T10:00:00'), ('device',''), ('kind','unknown')]
        for key, value in cases:
            e = fixture('PS-ATTACK')[0]; e[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError): detect([e])
        for value in (-1, True, '500'):
            e = fixture('FILE-ATTACK')[0]; e['changed_files'] = value
            with self.assertRaises(ValueError): detect([e])
        e = fixture('AUTH-ATTACK')[0]; e['src_ip'] = 'invalid'
        with self.assertRaises(ValueError): detect([e])

    def test_duplicate_event_ids_rejected(self):
        e = fixture('PS-ATTACK')[0]
        with self.assertRaises(ValueError): detect([e,e])

    def test_strict_json(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError): strict_json(value)

    def test_bounded_file_and_invalid_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'events.jsonl'
            p.write_bytes(b' '*(10*1024*1024+1))
            with self.assertRaises(ValueError): load_events(p)
            p.write_text('{broken}\n')
            with self.assertRaisesRegex(ValueError,'line 1'): load_events(p)

    def test_roundtrip_and_atomic_private_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'events.jsonl'
            events = generate()
            atomic_text(p, ''.join(json.dumps(e)+'\n' for e in events))
            self.assertEqual(load_events(p), events)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            link = Path(d)/'link'; link.symlink_to(p)
            with self.assertRaises(ValueError): atomic_text(link, 'replace')
            self.assertEqual(load_events(p), events)

    def test_metrics_reject_conflicting_or_missing_labels(self):
        events = fixture('AUTH-ATTACK'); events[0]['malicious'] = False
        with self.assertRaises(ValueError): evaluate(events, [])
        events = fixture('AUTH-ATTACK'); events[0].pop('malicious')
        with self.assertRaises(ValueError): evaluate(events, [])

if __name__ == '__main__': unittest.main()
