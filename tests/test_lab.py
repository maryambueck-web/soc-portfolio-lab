import copy
import unittest
from lab import generate,detect as _detect,evaluate
from datetime import datetime, timezone

def detect(events, tuned=False):
    return _detect(events, tuned, now=datetime(2026, 10, 28, tzinfo=timezone.utc))

class Tests(unittest.TestCase):
    def test_baseline_and_tuning(self):
        events=generate()
        self.assertEqual({k:evaluate(events,detect(events))[k] for k in ['TP','FP','FN','TN']},dict(TP=3,FP=1,FN=0,TN=3))
        self.assertEqual({k:evaluate(events,detect(events,True))[k] for k in ['TP','FP','FN','TN']},dict(TP=3,FP=0,FN=0,TN=4))
    def test_detection_does_not_need_truth(self):
        events=generate();expected=detect(events,True)
        for e in events:e.pop('malicious');e.pop('scenario')
        self.assertEqual(expected,detect(events,True))
    def test_exception_requires_all_fields(self):
        base=[e for e in generate() if e['scenario']=='PS-BACKUP'][0]
        for field in ['device','user','script_path','script_sha256']:
            e=copy.deepcopy(base);e[field]='different'
            self.assertEqual(len(detect([e],True)),1)
    def test_login_requires_same_ip(self):
        events=[e for e in generate() if e['scenario']=='AUTH-ATTACK'];events[-1]['src_ip']='192.0.2.99'
        self.assertEqual(detect(events),[])
    def test_login_window(self):
        events=[e for e in generate() if e['scenario']=='AUTH-ATTACK'];events[-1]['timestamp']='2026-01-01T10:30:00+00:00'
        self.assertEqual(detect(events),[])
    def test_file_requires_same_host(self):
        events=[e for e in generate() if e['scenario']=='FILE-ATTACK'];events[-1]['device']='OTHER'
        self.assertEqual(detect(events),[])
    def test_file_time_window(self):
        events=[e for e in generate() if e['scenario']=='FILE-ATTACK'];events[-1]['timestamp']='2026-01-01T10:35:00+00:00'
        self.assertEqual(detect(events),[])
    def test_harmless_logs(self):
        self.assertEqual(detect([e for e in generate() if e['scenario'] in ['PS-NORMAL','AUTH-TYPO','FILE-BACKUP']],True),[])
    def test_order_independent(self):
        events=generate();self.assertEqual(detect(events,True),detect(list(reversed(events)),True))

if __name__=='__main__':unittest.main()
