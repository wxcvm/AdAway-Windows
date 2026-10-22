"""Fail before compilation when dashboard control/command IDs alias by accident."""
from pathlib import Path
import re

source=Path(__file__).resolve().parents[1]/'gui_win32.c'
ids={}
for name,value in re.findall(r'^#define\s+((?:IDC|IDM)_\w+)\s+(\d+)\b',source.read_text(encoding='utf-8'),re.M):
    ids.setdefault(int(value),[]).append(name)
duplicates={key:names for key,names in ids.items() if len(names)>1}
assert not duplicates, f'Duplicate dashboard IDs: {duplicates}'
print(f'{len(ids)} explicit dashboard control/command IDs are unique')
