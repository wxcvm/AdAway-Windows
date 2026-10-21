"""Cache verification must reject edited source even if its manifest is rewritten."""
from pathlib import Path
import json,hashlib,subprocess,tempfile,shutil
repo=Path(__file__).resolve().parent.parent
script=repo/'fetch-tcp-contract.sh'
with tempfile.TemporaryDirectory(dir=repo) as temp:
    root=Path(temp);shutil.copytree(repo/'tcp-contract',root/'tcp-contract')
    assert subprocess.run(['bash',str(script)],cwd=root).returncode==0
    header=root/'tcp-contract/diagnostic_socks5.h'
    header.write_bytes(header.read_bytes()+b'\n/* modified */\n')
    manifest=root/'tcp-contract/manifest.json'
    data=json.loads(manifest.read_text());data['files'][header.name]=hashlib.sha256(header.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data))
    result=subprocess.run(['bash',str(script)],cwd=root,capture_output=True,text=True)
    assert result.returncode!=0 and 'TCP cache changed' in result.stderr
print('Independent TCP cache pin/hash rejects edited source + rewritten manifest')
