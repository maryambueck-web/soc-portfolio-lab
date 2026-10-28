"""Generate (never activate) a daily macOS user LaunchAgent for synthetic checks."""
import os
import plistlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safeio import atomic_text
root = Path(__file__).resolve().parents[1]
if sys.platform != 'darwin':
    raise SystemExit('Run this generator on your Mac after creating .venv.')
python = root/'.venv/bin/python'
if not python.exists():
    raise SystemExit('Create .venv first.')
os.umask(0o077)
agent = dict(Label='de.local.soc-portfolio-lab',
             ProgramArguments=[str(python), str(root/'pipeline.py')],
             WorkingDirectory=str(root), StartInterval=86400, RunAtLoad=False,
             StandardOutPath=str(root/'reports/scheduler.out.log'),
             StandardErrorPath=str(root/'reports/scheduler.err.log'), Umask=0o077)
path = root/'reports/local.launchagent.plist'
atomic_text(path, plistlib.dumps(agent).decode())
print('Prepared:', path)
print('Not activated. Follow README for activation/removal.')
