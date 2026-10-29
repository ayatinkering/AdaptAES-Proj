"""Local dependency-free API and static server. python3 -m api.server"""
from __future__ import annotations
import argparse
import json
import mimetypes
import multiprocessing as mp
import queue
import threading
import time
import uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from api import research

WEB=research.ROOT/'web/dist'
JOBS={}
LOCK=threading.Lock()


def worker(q,kind,seed,trials):
    try:
        result=research.experiments(kind,seed,trials,lambda x:q.put(('progress',x)))
        q.put(('result',result))
    except Exception as exc:q.put(('error',str(exc)))


def start_job(body):
    kind=body.get('kind','integral');seed=int(body.get('seed',20261029));trials=int(body.get('trials',1))
    if kind not in ['integral','differential','linear','substitution'] or not 1<=trials<=3:
        raise ValueError('Choose a supported experiment with 1–3 live trials.')
    if not 0<=seed<=2**32-1:raise ValueError('Seed must be an integer between 0 and 4294967295.')
    with LOCK:
        if any(j['state']=='running' for j in JOBS.values()):raise ValueError('Another experiment is running. Wait or cancel it first.')
        if len(JOBS)>=20:
            oldest=next(iter(JOBS));JOBS.pop(oldest)
        ident=uuid.uuid4().hex;ctx=mp.get_context('spawn');q=ctx.Queue();p=ctx.Process(target=worker,args=(q,kind,seed,trials),daemon=True)
        JOBS[ident]={'state':'running','completed':0,'total':trials*4,'process':p,'queue':q,'started':time.monotonic()}
        p.start()
    return {'id':ident}


def job_state(ident,cancel=False):
    with LOCK:
        if ident not in JOBS:raise ValueError('Experiment not found.')
        j=JOBS[ident]
        while True:
            try:kind,data=j['queue'].get_nowait()
            except queue.Empty:break
            if kind=='progress':j.update(data)
            elif kind=='result':j.update(state='done',result=data)
            else:j.update(state='failed',error=data)
        if j['state']=='running' and (cancel or time.monotonic()-j['started']>180):
            j['process'].terminate();j['process'].join(timeout=2);j.update(state='cancelled' if cancel else 'failed',error='Cancelled' if cancel else 'Experiment exceeded 180 seconds.')
        elif j['state']=='running' and not j['process'].is_alive():
            # Allow final queue feeder delivery before calling it an exit failure.
            try:
                kind,data=j['queue'].get(timeout=.2)
                if kind=='result':j.update(state='done',result=data)
                elif kind=='error':j.update(state='failed',error=data)
                else:j.update(data)
            except queue.Empty:j.update(state='failed',error='Experiment worker exited before returning a result.')
        return {k:v for k,v in j.items() if k not in ['process','queue','started']}


class Handler(BaseHTTPRequestHandler):
    server_version='AdaptAES/1.0'
    def log_message(self,*args):pass  # Inputs, keys and payloads are never logged.
    def respond(self,data,status=200):
        raw=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        parsed=urlparse(self.path);path=parsed.path
        try:
            if path=='/api/config':return self.respond({'modes':research.MODES,'max_bytes':65536,'archive':research.MANIFEST['archive'],'sha256':research.MANIFEST['sha256']})
            if path=='/api/results':return self.respond(research.recorded())
            if path.startswith('/api/experiments/'):return self.respond(job_state(path.rsplit('/',1)[-1]))
            if path=='/api/source':
                name=parse_qs(parsed.query).get('file',[''])[0]
                if name not in research.MANIFEST['files'] or not name.endswith(('.py','.txt','.csv')):raise ValueError('Choose an available source file.')
                return self.respond({'file':name,'content':(research.SOURCE/name).read_text(),'sha256':research.MANIFEST['files'][name]})
            if path=='/api/paper':return self.respond({'content':(research.ROOT/'docs/AdaptAES_full_project_report.md').read_text()})
            target=(WEB/('index.html' if path=='/' else path.lstrip('/'))).resolve()
            if not target.is_relative_to(WEB.resolve()) or not target.is_file():
                self.send_error(404);return
            raw=target.read_bytes();self.send_response(200);self.send_header('Content-Type',mimetypes.guess_type(target.name)[0] or 'application/octet-stream');self.send_header('Content-Length',str(len(raw)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'");self.end_headers();self.wfile.write(raw)
        except (ValueError,TypeError) as exc:self.respond({'error':str(exc)},400)
    def mutation(self,cancel=False):
        try:
            origin=self.headers.get('Origin')
            if origin and urlparse(origin).netloc!=self.headers.get('Host'):return self.respond({'error':'Only same-origin requests are accepted.'},403)
            if cancel:return self.respond(job_state(urlparse(self.path).path.rsplit('/',1)[-1],True))
            if self.headers.get_content_type()!='application/json':raise ValueError('Send application/json.')
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=200000:raise ValueError('Request exceeds the live input limit.')
            body=json.loads(self.rfile.read(size))
            if not isinstance(body,dict):raise ValueError('Send a JSON object.')
            if self.path=='/api/encrypt':return self.respond(research.encrypt_request(body))
            if self.path=='/api/compare':return self.respond(research.compare_request(body))
            if self.path=='/api/experiments':return self.respond(start_job(body),202)
            self.send_error(404)
        except (ValueError,TypeError,KeyError,OverflowError) as exc:self.respond({'error':str(exc)},400)
        except Exception:self.respond({'error':'The operation failed. Check inputs and retry.'},500)
    def do_POST(self):self.mutation()
    def do_DELETE(self):
        if not self.path.startswith('/api/experiments/'):return self.send_error(404)
        self.mutation(True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8000);args=parser.parse_args()
    if not (WEB/'index.html').exists():raise SystemExit('Build the frontend first: cd web && npm install && npm run build')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'AdaptAES workbench: http://127.0.0.1:{args.port}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:
        server.server_close()
        for j in JOBS.values():
            if j['process'].is_alive():j['process'].terminate();j['process'].join(timeout=2)

if __name__=='__main__':main()
