import re
import unittest
from pathlib import Path
from lab import ENCODED, ROOT

ALT = re.compile(r'\(\??:?(e\|ec\|en\|[a-z|]+)\)')

def alternation(text):
    found = ALT.findall(text)
    assert len(found) == 1, found
    return found[0]

class RuleSyncTests(unittest.TestCase):
    def test_python_kql_sigma_use_same_switch_list(self):
        py = alternation(ENCODED.pattern)
        for rel in ('queries/defender_powershell.kql', 'queries/sentinel_lab.kql', 'rules/encoded_powershell.yml'):
            with self.subTest(file=rel):
                self.assertEqual(alternation((ROOT / rel).read_text()), py)
    def test_slash_prefix_and_false_friends(self):
        for cmd in ('powershell /enc AAA', 'powershell -ec AAA', 'powershell "-ENC:AAA"'):
            self.assertIsNotNone(ENCODED.search(cmd), cmd)
        for cmd in ('powershell -ExecutionPolicy Bypass', 'powershell -encoding UTF8', 'powershell -Verbose'):
            self.assertIsNone(ENCODED.search(cmd), cmd)
    def test_sentinel_negative_controls_present(self):
        text = (ROOT / 'queries/sentinel_lab.kql').read_text()
        self.assertEqual(len(re.findall(r'"N00\d"', text)), 4)
        self.assertNotIn('contains "-enc"', text)

if __name__ == '__main__':
    unittest.main()
