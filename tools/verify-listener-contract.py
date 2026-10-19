"""Keep the independent listener contract pinned without rebasing the production service core."""
from pathlib import Path
import subprocess

ANDROID_REVISION='6b4920efff7207338827516ca659ec009e82b508'
root=Path(__file__).resolve().parent.parent
for name in ['listen_address.h','listen_address_test.c']:
    url=f'https://raw.githubusercontent.com/wxcvm/AdAway/{ANDROID_REVISION}/webserver/jni/{name}'
    expected=subprocess.check_output(['curl','--fail','--silent','--show-error','--retry','3',url])
    actual=(root/name).read_bytes().replace(b'\r\n',b'\n')
    if expected.replace(b'\r\n',b'\n')!=actual:
        raise ValueError('Listener contract differs from pinned Android revision: '+name)
print('Listener behavior pinned independently at Android '+ANDROID_REVISION+'; portable core 4470606 unchanged')
