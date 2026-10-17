#!/usr/bin/env python3
import argparse, http.server, json, pathlib, runpy, shutil, socket, subprocess, sys, tempfile, threading
ROOT=pathlib.Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(); ap.add_argument('test',choices=['greenmark','ugate','gate','lanes']); a=ap.parse_args()
with tempfile.TemporaryDirectory() as td:
 p=pathlib.Path(td)
 for name in ['shield','greenmark']:
  shutil.copytree(ROOT/name,p/name,ignore=shutil.ignore_patterns('__pycache__','results'))
 (p/'shield/results').mkdir()
 if a.test in ['greenmark','ugate']:
  folder='greenmark' if a.test=='greenmark' else 'shield'
  name='test_'+a.test
  cp=subprocess.run([sys.executable,str(p/folder/(name+'.py'))],capture_output=True,text=True)
  assert cp.returncode==0,cp.stderr
  result=json.loads((p/folder/(name+'.result.json')).read_text())
 elif a.test=='gate':
  class Quiet(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    self.send_response(200); self.end_headers(); self.wfile.write(b'owned')
   def log_message(self,*args): pass
  srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),Quiet)
  th=threading.Thread(target=srv.serve_forever,daemon=True); th.start()
  with socket.socket() as sock:
   sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
  ns=runpy.run_path(str(p/'shield/test_gate.py'))
  ns['main'].__globals__.update(UP=('127.0.0.1',srv.server_port),LISTEN=('127.0.0.1',port))
  try: ns['main']()
  finally: srv.shutdown(); srv.server_close(); th.join()
  result=json.loads((p/'shield/test_gate.result.json').read_text())
 else:
  sys.path[:0]=[str(p/'shield'),str(p/'greenmark')]
  import lanes, greenmark as gm
  payloads=json.loads((ROOT/'tests/payloads.json').read_text())
  envs=[lanes.seal(x['payload'],source='untrusted') for x in payloads]
  assert envs and all(not lanes.may_instruct(e) and 'instructions="not permitted"' in lanes.render(e) for e in envs)
  sk=bytes(range(32)); msg=b'Run the local test'; marks=lanes.sign_content(sk,'test',msg)
  trusted={'test':gm.public_key(sk)}
  assert lanes.may_instruct(lanes.seal(msg,source='fleet',kind='message',marks=marks,trusted=trusted))
  assert lanes.seal(msg+b'x',source='fleet',kind='message',marks=marks,trusted=trusted)['verdict']==-1
  assert lanes.seal(msg,source='fleet',kind='message',marks=marks,trusted=trusted,revoked={'test'})['verdict']==-1
  result={'verdict':'PASS','unsigned_payloads':len(envs),'unsigned_instructions':0}
 assert result['verdict']=='PASS',result
 print(json.dumps(result))
