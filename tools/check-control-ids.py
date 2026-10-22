"""Fail before compilation when dashboard control/command IDs alias by accident."""
from pathlib import Path
import re

source=Path(__file__).resolve().parents[1]/'gui_win32.c'
text=source.read_text(encoding='utf-8')
ids={}
for name,value in re.findall(r'^#define\s+((?:IDC|IDM)_\w+)\s+(\d+)\b',text,re.M):
    ids.setdefault(int(value),[]).append(name)
duplicates={key:names for key,names in ids.items() if len(names)>1}
assert not duplicates, f'Duplicate dashboard IDs: {duplicates}'
print(f'{len(ids)} explicit dashboard control/command IDs are unique')
for page in ('g_clayout','g_sublayout','g_loglayout'):
    body=re.search(r'static const struct ctl_desc '+page+r'\[\] = \{(.*?)\n\};',text,re.S).group(1)
    rectangles=[]
    for name,x,y,width,height,kind in re.findall(r'\{\s*(\w+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*L"(\w+)"',body):
        x,y,width,height=map(int,(x,y,width,height))
        # A closed drop-down's visible height follows its font; the descriptor
        # height reserves its popup, which is not a page child rectangle.
        if kind=='COMBOBOX':height=28
        rectangles.append((name,x,y,x+width,y+height))
    if page=='g_clayout':
        policy=re.search(r'static const struct policy_item g_policy\[\] = \{(.*?)\n\};',text,re.S).group(1)
        count=len(re.findall(r'\{[^}]+\}',policy))
        for i in range(count):
            x=218 if i%2==0 else 610;y=290+(i//2)*28
            rectangles.append((f'policy[{i}]',x,y,x+370,y+26))
    for i,a in enumerate(rectangles):
        assert a[1]>=202 and a[2]>=0 and a[3]<=1014 and a[4]<=632,(page,a)
        for b in rectangles[i+1:]:
            assert not(a[1]<b[3] and a[3]>b[1] and a[2]<b[4] and a[4]>b[2]),(page,'overlap',a[0],b[0])
    print(f'{page}: {len(rectangles)} visible rectangles fit without overlap')
