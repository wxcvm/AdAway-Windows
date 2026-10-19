import json
import os
import socket
import subprocess
import sys
for version,ip in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
    with socket.socket(version,socket.SOCK_STREAM) as server:
        server.bind((ip,0)); server.listen()
        port=server.getsockname()[1]
        result=json.loads(subprocess.check_output([sys.argv[1],ip,str(port)],text=True))
        assert result['status']==1 and result['pid']==os.getpid(),result
    result=json.loads(subprocess.check_output([sys.argv[1],ip,str(port)],text=True))
    assert result['status']==0 and result['pid']==0,result
print('Real other-process PID detection and release, IPv4 + IPv6, passed')
