"""Pin only the stateless receipt header; keep production portable core unchanged."""
from pathlib import Path
import subprocess

REVISION = 'd60b921c804f0cdcafd07047973af04edebb73fa'
root = Path(__file__).resolve().parent.parent
name = 'listener_arrival_probe.h'
expected = subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--retry', '3',
    f'https://raw.githubusercontent.com/wxcvm/AdAway/{REVISION}/webserver/jni/{name}'])
if expected.replace(b'\r\n', b'\n') != (root / name).read_bytes().replace(b'\r\n', b'\n'):
    raise ValueError('Receipt header differs from independently pinned Android revision')
print('Stateless receipt header verified at Android ' + REVISION + '; portable core 4470606 unchanged')
