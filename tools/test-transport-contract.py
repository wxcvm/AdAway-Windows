"""Cache verification must reject edited source even if its manifest is rewritten."""
from pathlib import Path
import json,hashlib,subprocess,tempfile,shutil
repo=Path(__file__).resolve().parent.parent
script=repo/'fetch-transport-contract.sh'
with tempfile.TemporaryDirectory(dir=repo) as temp:
    root=Path(temp);shutil.copytree(repo/'transport-contract',root/'transport-contract')
    assert subprocess.run(['bash',str(script)],cwd=root).returncode==0
    header=root/'transport-contract/diagnostic_udp_packet.h'
    header.write_bytes(header.read_bytes()+b'\n/* modified */\n')
    manifest=root/'transport-contract/manifest.json'
    data=json.loads(manifest.read_text());data['files'][header.name]=hashlib.sha256(header.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data))
    result=subprocess.run(['bash',str(script)],cwd=root,capture_output=True,text=True)
    assert result.returncode!=0 and 'Transport cache changed' in result.stderr
print('Independent transport cache pin/hash rejects edited source + rewritten manifest')
