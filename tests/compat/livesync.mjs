// Real, unmodified upstream Commonlib + PouchDB clients. Only generated disposable data.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import PouchDB from 'pouchdb-core';
import Http from 'pouchdb-adapter-http';
import Memory from 'pouchdb-adapter-memory';
import Replication from 'pouchdb-replication';
import { DirectFileManipulator } from '@vrtmrz/livesync-commonlib';
import { checkRemoteVersion } from '@vrtmrz/livesync-commonlib/compat/pouchdb/negotiation';
import { readAsBlob } from '@vrtmrz/livesync-commonlib/compat/common/utils';
PouchDB.plugin(Http).plugin(Memory);
// Commonlib installs replication on the shared PouchDB constructor as a module side effect.
if(!Object.getOwnPropertyDescriptor(PouchDB.prototype,'replicate')) PouchDB.plugin(Replication);
const url=process.env.LS_TEST_URL;
const username=process.env.LS_TEST_USER;
const password=process.env.LS_TEST_TOKEN;
assert.ok(url?.startsWith('http://127.0.0.1:'),'Disposable loopback-only fixture required');
const encryptionPassword=process.env.LS_TEST_E2EE_PASSPHRASE;
assert.ok(encryptionPassword?.length>=32,'A generated disposable E2EE passphrase is required');
const auth={username,password};
const peerAuth={username:process.env.LS_TEST_PEER_USER??username,password:process.env.LS_TEST_PEER_TOKEN??password};
const headers={authorization:`Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`};
const phase=process.env.LS_TEST_PHASE??'initial';
const stateFile=process.env.LS_TEST_STATE;
const remote=new PouchDB(`${url}/vault`,{adapter:'http',auth,skip_setup:true});
const report=(test)=>console.log(JSON.stringify({test,status:'passed'}));
const replicate=async(source,target)=>{const result=await source.replicate.to(target,{batch_size:7,batches_limit:2});assert.equal(result.ok,true);};
async function fileText(file){assert.ok(file,'Expected Commonlib entry');assert.equal(file.deleted??false,false);return file.data instanceof Blob?await file.data.text():Array.isArray(file.data)?file.data.join(''):file.data;}
const options={url,database:'vault',username,password,enableCompression:false,useDynamicIterationCount:false,handleFilenameCaseSensitive:true,hashAlg:'xxhash64',minimumChunkSize:20};
async function commonFileRoundtrip(options, path, content){
  const first=new DirectFileManipulator(options);let second=new DirectFileManipulator(options);
  try{
    await first.ready.promise;await second.ready.promise;
    const bytes=new TextEncoder().encode(content);const now=Date.now();
    assert.equal(await first.put(path,content,{ctime:now,mtime:now,size:bytes.length}),true);
    assert.equal(await fileText(await second.get(path)),content);
    const body='updated: '+content.slice(0,4000);
    assert.equal(await second.put(path,body,{ctime:now,mtime:now+1,size:Buffer.byteLength(body)}),true);
    assert.equal(await fileText(await first.get(path)),body);
    const moved=path.replace('.md','-moved.md');
    assert.equal(await first.put(moved,body,{ctime:now,mtime:now+2,size:Buffer.byteLength(body)}),true);
    assert.equal(await first.delete(path),true);
    // Commonlib 0.1.44's warm compressed-chunk cache returns compressed markers after
    // this move on BOTH Apache CouchDB 3.5.0 and Rust. Verify durable bytes through
    // a fresh reader; retain this upstream limitation in the compatibility report.
    await second.close();second=new DirectFileManipulator(options);await second.ready.promise;
    const original=await second.get(path);assert.ok(!original||original.deleted,'Logical deletion must be reflected');
    assert.equal(await fileText(await second.get(moved)),body);
    report(`Commonlib read/write/logical-delete/move: ${options.database}`);
  }finally{await first.close();await second.close();}
}
if(phase==='restart'){
  const state=JSON.parse(await readFile(stateFile,'utf8'));
  assert.equal((await remote.info()).update_seq,state.sequence);
  assert.equal((await remote.get('_local/restart-checkpoint')).last_seq,state.sequence);
  const revisions=await remote.get('offline.md',{open_revs:'all',revs:true});
  assert.equal(revisions.length,2);assert.deepEqual(revisions.map(r=>r.ok.data).sort(),['device A','device B']);
  const fresh=new PouchDB(`restart-${randomUUID()}`,{adapter:'memory'});
  await replicate(remote,fresh);assert.equal((await fresh.get('offline.md',{conflicts:true}))._conflicts.length,1);
  await fresh.destroy();await remote.close();
  const encrypted=new DirectFileManipulator({...options,database:'encrypted',username:process.env.LS_TEST_ENCRYPTED_USER,password:process.env.LS_TEST_ENCRYPTED_TOKEN,passphrase:encryptionPassword,E2EEAlgorithm:'v2',enableCompression:true});
  try {await encrypted.ready.promise;assert.equal(await fileText(await encrypted.get('secret-note-moved.md')),'updated: '+'Private fixture content 🌊\n'.repeat(60));} finally {await encrypted.close();}
  report('Restart: persistent revisions, conflict branches, sequence/checkpoint and E2EE/compressed file');
  process.exit(0);
}
{
  const bootstrapAuth={username:process.env.LS_TEST_BOOTSTRAP_USER,password:process.env.LS_TEST_BOOTSTRAP_TOKEN};
  const previous=new PouchDB(`${url}/bootstrap`,{adapter:'http',auth:bootstrapAuth});
  await previous.put({_id:'before-initialisation',value:'retained by Rust archive'});
  await previous.put({_id:'_local/old-checkpoint',last_seq:'old'});
  await previous.destroy();
  const recreated=new PouchDB(`${url}/bootstrap`,{adapter:'http',auth:bootstrapAuth});
  assert.equal((await recreated.info()).doc_count,0);await assert.rejects(recreated.get('_local/old-checkpoint'),e=>e.status===404);
  await recreated.put({_id:'initialised',value:'new generation'});await recreated.close();
  report('LiveSync bootstrap destroy/recreate: same scoped credentials, fresh database and checkpoints');
}
assert.equal((await remote.info()).doc_count,0);
assert.equal(await checkRemoteVersion(remote,async()=>false),true);
const peerRemote=new PouchDB(`${url}/vault`,{adapter:'http',auth:peerAuth,skip_setup:true});
const a=new PouchDB(`device-a-${randomUUID()}`,{adapter:'memory'});
const b=new PouchDB(`device-b-${randomUUID()}`,{adapter:'memory'});
try{
  await a.put({_id:'offline.md',type:'plain',data:'base'});await replicate(a,remote);await replicate(remote,b);
  const left=await a.get('offline.md');const right=await b.get('offline.md');
  await a.put({...left,data:'device A'});await b.put({...right,data:'device B'});
  await replicate(b,peerRemote);await replicate(a,remote);await replicate(remote,a);await replicate(peerRemote,b);
  for(const database of [a,b,remote]){
    const leaves=await database.get('offline.md',{open_revs:'all',revs:true});
    assert.deepEqual(leaves.map(r=>r.ok.data).sort(),['device A','device B']);
    assert.equal((await database.get('offline.md',{conflicts:true}))._conflicts.length,1);
  }
  report('PouchDB bidirectional offline replication preserves competing revision trees');
  const winner=await remote.get('offline.md');
  const requests=await Promise.allSettled([remote.put({...winner,_id:'offline.md',data:'attempt-1'}),remote.put({...winner,_id:'offline.md',data:'attempt-2'})]);
  assert.equal(requests.filter(r=>r.status==='fulfilled').length,1);assert.equal(requests.filter(r=>r.status==='rejected'&&r.reason.status===409).length,1);
  // Restore the conflict fixture expected after restart, preserving the losing branch.
  const next=await remote.get('offline.md');await remote.put({...next,data:winner.data});
  report('PouchDB CAS: simultaneous normal updates return one success and one conflict');
  const docs=Array.from({length:37},(_,index)=>({_id:`page-${String(index).padStart(3,'0')}`,type:index%2?'plain':'leaf',data:`value-${index}`}));
  await a.bulkDocs(docs);await replicate(a,remote);const fresh=new PouchDB(`paged-${randomUUID()}`,{adapter:'memory'});await replicate(remote,fresh);assert.equal((await fresh.allDocs({startkey:'page-',endkey:'page-\uffff'})).rows.length,37);await fresh.destroy();
  const selection=await remote.changes({since:0,include_docs:true,selector:{type:{$ne:'leaf'}}});assert.ok(selection.results.length>0);assert.ok(selection.results.every(r=>r.doc.type!=='leaf'));report('PouchDB multi-page changes, bulk-get and on-demand non-chunk selector');
  await commonFileRoundtrip(options,'unicode/日本語 café.md','Notes: 日本語, café, emoji 🌊\n'.repeat(60));
  {
    const client=new DirectFileManipulator(options);await client.ready.promise;
    try {
      const data=Buffer.alloc(3*1024*1024);for(let index=0;index<data.length;index++)data[index]=index%251;
      const now=Date.now();assert.equal(await client.put('attachment.bin',new Blob([data],{type:'application/octet-stream'}),{ctime:now,mtime:now,size:data.length}),true);
      const entry=await client.get('attachment.bin');assert.deepEqual(Buffer.from(await readAsBlob(entry).arrayBuffer()),data);
      report('Commonlib large binary attachment: 3 MiB chunked/decoded byte equality');
    } finally {await client.close();}
  }
  await commonFileRoundtrip({...options,database:'encrypted',username:process.env.LS_TEST_ENCRYPTED_USER,password:process.env.LS_TEST_ENCRYPTED_TOKEN,passphrase:encryptionPassword,E2EEAlgorithm:'v2',enableCompression:true},'secret-note.md','Private fixture content 🌊\n'.repeat(60));
  {
    const encryptedOptions={...options,database:'encrypted',username:process.env.LS_TEST_ENCRYPTED_USER,password:process.env.LS_TEST_ENCRYPTED_TOKEN,passphrase:encryptionPassword,E2EEAlgorithm:'v2',enableCompression:true};
    const client=new DirectFileManipulator(encryptedOptions);await client.ready.promise;
    const raw=new PouchDB(`${url}/encrypted`,{adapter:'http',auth:{username:encryptedOptions.username,password:encryptedOptions.password},skip_setup:true});
    try {
      const salt=await client.getReplicationPBKDF2Salt(client.settings,false);
      const {getConfiguredFunctionsForEncryption}=await import(new URL('./pouchdb/encryption.js',import.meta.resolve('@vrtmrz/livesync-commonlib')));
      const transforms=getConfiguredFunctionsForEncryption(encryptedOptions.passphrase,false,false,async()=>salt,'v2');
      const doc={_id:`h:+retry-${randomUUID()}`,_rev:`1-${randomUUID().replaceAll('-','')}`,type:'leaf',data:'same plaintext, fresh encryption nonce'};
      const one=await transforms.incoming(structuredClone(doc));const two=await transforms.incoming(structuredClone(doc));
      assert.notEqual(one.data,two.data,'Upstream encryption must use fresh random IV/salt');
      for(const encrypted of [one,two]){const result=await raw.bulkDocs([encrypted],{new_edits:false});assert.ok(result.every(r=>!r.error),'A duplicate revision with fresh encryption randomness is a successful CouchDB replay');}
      const saved=await raw.get(doc._id);assert.equal(saved.data,one.data,'First immutable body must remain untouched');assert.equal((await transforms.outgoing(saved)).data,doc.data);
      report('Actual Commonlib E2EE: duplicate imported revision with fresh IV/salt preserves first body');
    } finally {await raw.close();await client.close();}
  }
  {
    // Exercise the exact published internal Fast Fetch helper used by LiveSync,
    // not a hand-written replacement for its NDJSON/checkpoint handling.
    const {fetchChangesForInitialSync}=await import(new URL('./pouchdb/StreamingFetch.js',import.meta.resolve('@vrtmrz/livesync-commonlib')));
    const target=new PouchDB(`fast-${randomUUID()}`,{adapter:'memory'});let checkpoint;
    try {
      await fetchChangesForInitialSync(target,`${url}/vault`,headers.authorization,async doc=>doc,'0',undefined,async seq=>{checkpoint=seq;});
      assert.equal((await target.info()).doc_count,(await remote.info()).doc_count);assert.ok(checkpoint!==undefined);assert.equal((await remote.changes({since:checkpoint})).results.length,0);
      await replicate(remote,target);assert.equal((await target.get('offline.md',{conflicts:true}))._conflicts.length,1);
      report('Actual LiveSync Fast Fetch: bounded continuous NDJSON, ancestry and checkpoints');
    } finally {await target.destroy();}
  }
  const since=(await remote.info()).update_seq;
  const live=remote.changes({since,live:true,include_docs:true,timeout:4000,heartbeat:false});
  const observed=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Live change not observed')),6000);live.on('change',r=>{if(r.id==='live-notification'){clearTimeout(timer);resolve(r);}}).on('error',reject);});
  await remote.put({_id:'live-notification',data:'wake'});await observed;live.cancel();report('PouchDB live long-poll wakeup');
  const sequence=(await remote.info()).update_seq;
  await remote.put({_id:'_local/restart-checkpoint',last_seq:sequence});await writeFile(stateFile,JSON.stringify({sequence}));
}finally{await a.destroy();await b.destroy();await remote.close();await peerRemote.close();}
// Commonlib owns long-lived maintenance timers; all assertions and awaited writes finished.
process.exit(0);
