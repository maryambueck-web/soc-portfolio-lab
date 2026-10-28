"""Optional UI regression check. Run pipeline.py first; requires Streamlit."""
import os
from pathlib import Path
from streamlit.testing.v1 import AppTest
os.chdir(Path(__file__).resolve().parents[1])
at = AppTest.from_file(str(Path.cwd()/'app.py')).run(timeout=30)
assert not at.exception, at.exception
assert [m.value for m in at.metric] == ['3','1','0','3']
at.toggle[0].set_value(True).run()
assert not at.exception
assert [m.value for m in at.metric] == ['3','0','0','4']
at.text_area[0].set_value('Belege geprüft. Tabletop: Eindämmung vorschlagen.').run()
at.selectbox[1].set_value('Weitere Untersuchung').run()
at.selectbox[0].set_value(1).run()
assert at.text_area[0].value == ''
assert at.selectbox[1].value == 'Offen'
at.selectbox[0].set_value(0).run()
assert at.text_area[0].value.startswith('Belege geprüft.')
assert at.selectbox[1].value == 'Weitere Untersuchung'
print('Dashboard baseline/tuning and per-alert draft retention: PASS')
