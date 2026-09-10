"""Disposable route-engine check; loopback egresses isolate routing from VPN transport."""
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from routing import compile_config

class Response(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data=b''
        while b'\r\n\r\n' not in data:
            packet = self.request.recv(4096)
            if not packet or len(data) > 16384:
                return
            data += packet
        body=self.client_address[0].encode()
        self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

base={'log':{'level':'error'},'inbounds':[{'type':'socks','tag':'vpn-clients','listen':'127.0.0.1','listen_port':18081}],
      'outbounds':[{'type':'direct','tag':'eu-direct','inet4_bind_address':'127.0.0.10'}, {'type':'direct','tag':'ru-direct'}],
      'route':{'rules':[{'inbound':'vpn-clients','action':'sniff','sniffer':['http'],'timeout':'1s'}],'final':'eu-direct'}}
exits=[{'id':n,'legacy':1} for n in (1,2,3)]
devices=[{'id':1,'account_id':'one','vpn_ip':'127.0.1.2','ru_exit_id':3,'account_ru_exit_id':2},
         {'id':2,'account_id':'two','vpn_ip':'127.0.1.3','ru_exit_id':None,'account_ru_exit_id':None}]


def query(name, source='127.0.1.2'):
    with socket.socket() as client:
        client.settimeout(3); client.bind((source,0)); client.connect(('127.0.0.1',18081))
        client.sendall(b'\x05\x01\x00'); assert client.recv(2)==b'\x05\x00'
        client.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+(18080).to_bytes(2,'big'))
        result=client.recv(10)
        if len(result)<2 or result[1]: return 'blocked'
        client.sendall(f'GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n'.encode())
        data=b''
        try:
            while packet:=client.recv(4096): data+=packet
        except (ConnectionError,TimeoutError): return 'blocked'
        return data.partition(b'\r\n\r\n')[2].decode() or 'blocked'


def rule(scope,target,kind,value,owner=''):
    return {'scope':scope,'target':target,'kind':kind,'value':value,'owner_id':owner}


def run_case(root,label,rules,health,expected):
    started=time.perf_counter()
    config=compile_config(base,exits,devices,rules,1,health,'lo',root)
    # The tested match/action lists are unmodified; deterministic local source
    # addresses replace tunnel transport so no external node is touched.
    config['inbounds'][0].pop('include_interface',None)
    for outbound in config['outbounds']:
        if outbound['tag'].startswith('ru-'):
            outbound.pop('bind_interface',None)
            outbound['inet4_bind_address']='127.0.0.'+str(10+int(outbound['tag'][3:]))
    path=root/'config.json'; path.write_text(json.dumps(config))
    subprocess.run(['sing-box','check','-c',str(path)],check=True,capture_output=True)
    generation=(time.perf_counter()-started)*1000
    process=subprocess.Popen(['sing-box','run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',18081),timeout=.05): break
            except OSError: time.sleep(.02)
        for host,source,result in expected:
            observed=query(host,source)
            assert observed==result,(label,host,observed,result)
        print(label+': passed; compile/check '+str(round(generation,2))+' ms',flush=True)
    finally:
        process.terminate(); process.wait(timeout=5)


def main():
    all_up={'1':True,'2':True,'3':True}
    with Server(('127.0.0.1',18080),Response) as server, tempfile.TemporaryDirectory() as temporary:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        root=Path(temporary)
        rules=[rule('global','ru','domain','specific.example.test'),rule('account','direct','suffix','example.test','one'),rule('device','ru','suffix','test','1')]
        run_case(root,'Device level beats more specific account/global',rules,all_up,[('specific.example.test','127.0.1.2','127.0.0.13'),('specific.example.test','127.0.1.3','127.0.0.11')])
        run_case(root,'Account level beats global',rules[:-1],all_up,[('specific.example.test','127.0.1.2','127.0.0.10')])
        rules=[rule('global','ru','suffix','test')]
        for label,health,egress in [('device',all_up,'127.0.0.13'),('account',{'1':True,'2':True,'3':False},'127.0.0.12'),('global',{'1':True,'2':False,'3':False},'127.0.0.11'),('blocked',{},'blocked'),('recovered',all_up,'127.0.0.13')]:
            run_case(root,'RU chain '+label,rules,health,[('route.test','127.0.1.2',egress)])
        run_case(root,'No rule uses main VPS',[],all_up,[('route.test','127.0.1.2','127.0.0.10')])
        server.shutdown()

if __name__=='__main__': main()
