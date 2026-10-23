#!/usr/bin/env python3
"""Optional differential check: run the exact client fixture against disposable Apache CouchDB."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
name='obsidian-sync-reference-'+secrets.token_hex(6)
username='fixture-user'
password=secrets.token_hex(32)
image='couchdb:3.5.0@sha256:1c0a30a54535377bc9ae23f42efb1ca4e92abe796f78ec98b768ac1d5874cc1b'
headers={'Authorization':'Basic '+base64.b64encode(f'{username}:{password}'.encode()).decode(),'Content-Type':'application/json'}
try:
    subprocess.run(['docker','run','--rm','-d','--name',name,'-e','COUCHDB_USER','-e','COUCHDB_PASSWORD','-p','127.0.0.1::5984','--tmpfs','/opt/couchdb/data:uid=5984,gid=5984,mode=0700',image],env={**os.environ,'COUCHDB_USER':username,'COUCHDB_PASSWORD':password},check=True,stdout=subprocess.DEVNULL)
    port=subprocess.check_output(['docker','port',name,'5984'],text=True).strip().rsplit(':',1)[1]
    url=f'http://127.0.0.1:{port}'
    for _ in range(120):
        try:urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=2);break
        except OSError:time.sleep(.5)
    else:raise RuntimeError('Reference CouchDB did not start')
    def request(path,method,body=None):
        data=json.dumps(body).encode() if body else None
        with urllib.request.urlopen(urllib.request.Request(url+path,method=method,headers=headers,data=data),timeout=30)as response:return json.load(response)
    request('/_node/_local/_config/cluster/n','PUT','1')
    request('/vault?n=1','PUT');request('/encrypted?n=1','PUT');request('/bootstrap?n=1','PUT')
    with tempfile.TemporaryDirectory()as work:
        env={**os.environ,'LS_TEST_URL':url,'LS_TEST_USER':username,'LS_TEST_TOKEN':password,'LS_TEST_ENCRYPTED_USER':username,'LS_TEST_ENCRYPTED_TOKEN':password,'LS_TEST_E2EE_PASSPHRASE':secrets.token_urlsafe(32),'LS_TEST_BOOTSTRAP_USER':username,'LS_TEST_BOOTSTRAP_TOKEN':password,'LS_TEST_STATE':str(Path(work)/'state.json')}
        subprocess.run(['node','tests/compat/livesync.mjs'],cwd=ROOT,env=env,check=True,timeout=180)
finally:
    subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
