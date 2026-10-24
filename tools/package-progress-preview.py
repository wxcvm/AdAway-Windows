"""Package an in-place preview using the production installer identity."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import re
root=Path(__file__).resolve().parent.parent
output=root/'release-assets'
output.mkdir(exist_ok=True)
files={
    'adblock-webserver-setup.exe': root/'dist-installer/adblock-webserver-setup.exe',
    'adblock-webserver-win64.zip': root/'adblock-webserver-win64.zip',
}
for name,source in files.items():
    if not source.is_file() or source.stat().st_size<100_000:
        raise ValueError('Missing required in-place preview artifact: '+name)
    shutil.copyfile(source,output/name)
script=(root/'tools/install-preview.ps1').read_text(encoding='utf-8')
script=script.replace('@@TAG@@',os.environ['PREVIEW_TAG']).replace(
    '@@INSTALLER_SHA@@',hashlib.sha256((output/'adblock-webserver-setup.exe').read_bytes()).hexdigest())
if '@@' in script: raise ValueError('Unexpanded installer identity')
(output/'install-preview.ps1').write_text(script,encoding='utf-8-sig')
shutil.copyfile(root/'docs/preview-installation.md',output/'INSTALLATION.md')
(output/'IMPLEMENTATION-STATUS.md').write_text('\n'.join((root/'docs'/name).read_text(encoding='utf-8') for name in ['listener-settings.md','listener-lifecycle.md','listener-arrival.md','dual-stack-transport.md','query-log-paging.md']),encoding='utf-8')
(output/'SOURCE-COMMIT.txt').write_text(os.environ['GITHUB_SHA']+'\n',encoding='utf-8')
(output/'SIGNING-POLICY.txt').write_text(
    'Unsigned Windows distribution; SHA-256 verifies download integrity, not publisher identity.\n'
    if os.environ.get('WINDOWS_UNSIGNED_RELEASE')=='1' else 'Production publisher signature verified in CI.\n',encoding='utf-8')
version=re.search(r'#define ADBLOCK_APP_VERSION "([0-9.]+)"', (root/'gui_win32.h').read_text(encoding='utf-8'))[1]
tag=os.environ['PREVIEW_TAG']
build=os.environ['GITHUB_RUN_ID']
if not re.fullmatch(r'progress-win-[0-9]{8}\.[0-9]+',tag) or not build.isdecimal():
    raise ValueError('Invalid preview update identity')
base=f'https://github.com/wxcvm/AdAway-Windows/releases/download/{tag}'
manifest=dict(channel='preview',tag=tag,version=version,build=build,sourceCommit=os.environ['GITHUB_SHA'])
for key,name in [('exe','adblock-webserver-setup.exe'),('zip','adblock-webserver-win64.zip')]:
    manifest[key+'_url']=base+'/'+name
    manifest[key+'_sha256']='sha256:'+hashlib.sha256((output/name).read_bytes()).hexdigest()
(output/'windows-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
(output/'SHA256SUMS.txt').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
    for p in sorted(output.iterdir()) if p.is_file() and p.name!='SHA256SUMS.txt'),encoding='utf-8')
print('Production AppId installer, ZIP, pinned installer script and checksums prepared')
