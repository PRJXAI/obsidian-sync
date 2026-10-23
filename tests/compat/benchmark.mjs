// Test-only real Commonlib/PouchDB benchmark; setup/crypto generation excluded from timers.
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {DirectFileManipulator} from '@vrtmrz/livesync-commonlib';
import {readAsBlob} from '@vrtmrz/livesync-commonlib/compat/common/utils';
import PouchCore from 'pouchdb-core';
import http from 'pouchdb-adapter-http';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const options={url:process.env.LS_TEST_URL,database:'vault',username:process.env.LS_TEST_USER,password:process.env.LS_TEST_TOKEN,enableCompression:false,useDynamicIterationCount:false,handleFilenameCaseSensitive:true,hashAlg:'xxhash64',minimumChunkSize:20};
assert.ok(options.url?.startsWith('http://127.0.0.1:'),'Disposable loopback service only');
const remote=new(PouchCore.plugin(http))(`${options.url}/vault`,{auth:{username:process.env.LS_TEST_PEER_USER,password:process.env.LS_TEST_PEER_TOKEN},skip_setup:true});
const main=new DirectFileManipulator(options);
const writers=[];
const clients=JSON.parse(process.env.LS_TEST_BENCHMARK_KEYS);
const metadata=size=>({ctime:Date.now(),mtime:Date.now(),size});
function report(workload,samples,elapsed,bytes=0){
  const sorted=[...samples].sort((a,b)=>a-b),at=q=>sorted[Math.min(sorted.length-1,Math.ceil(q*sorted.length)-1)];
  console.log(JSON.stringify({benchmark:workload,samples:samples.length,elapsed_ms:+elapsed.toFixed(3),operations_per_sec:+(samples.length*1000/elapsed).toFixed(3),logical_mib_per_sec:bytes?+(bytes/(1024*1024)/(elapsed/1000)).toFixed(3):undefined,p50_ms:+at(.5).toFixed(3),p95_ms:+at(.95).toFixed(3),p99_ms:+at(.99).toFixed(3)}));
}
try {
  await main.ready.promise;
  const small=[];let start=performance.now();
  for(let i=0;i<50;i++){
    const text=`${i}:`+'n'.repeat(1024),t=performance.now();
    assert.equal(await main.put(`notes/${i}.md`,text,metadata(text.length)),true);small.push(performance.now()-t);
  }
  report('1 KiB logical notes: actual Commonlib chunking + durable HTTP writes',small,performance.now()-start);
  const uploads=[],downloads=[];
  for(let i=0;i<5;i++){
    const bytes=new Uint8Array(3*1024*1024);
    for(let j=0;j<bytes.length;j+=65536)crypto.getRandomValues(bytes.subarray(j,Math.min(j+65536,bytes.length)));
    const blob=new Blob([bytes],{type:'application/octet-stream'}),name=`assets/${i}.bin`;
    let t=performance.now();assert.equal(await main.put(name,blob,metadata(bytes.length)),true);uploads.push(performance.now()-t);
    const fresh=new DirectFileManipulator(options);
    try {
      await fresh.ready.promise;t=performance.now();const entry=await fresh.get(name);assert.ok(entry);
      const result=new Uint8Array(await readAsBlob(entry).arrayBuffer());downloads.push(performance.now()-t);assert.deepEqual(result,bytes);
    } finally {await fresh.close();}
  }
  report('3 MiB unique binary: actual chunked durable HTTP upload',uploads,uploads.reduce((a,b)=>a+b,0),uploads.length*3*1024*1024);
  report('3 MiB binary: fresh-client HTTP chunk read and reconstruction',downloads,downloads.reduce((a,b)=>a+b,0),downloads.length*3*1024*1024);
  for(const key of clients){const writer=new DirectFileManipulator({...options,username:key.principal,password:key.token});await writer.ready.promise;writers.push(writer);}
  const concurrent=[];start=performance.now();
  await Promise.all(writers.map(async(writer,device)=>{
    for(let i=0;i<25;i++){
      const text=`${device}/${i}:`+'c'.repeat(1024),t=performance.now();assert.equal(await writer.put(`concurrent/${device}/${i}.md`,text,metadata(text.length)),true);concurrent.push(performance.now()-t);
    }
  }));
  report('8 independently authenticated concurrent writers, 25 logical notes each',concurrent,performance.now()-start);
  // A fresh reader identity and unmeasured budget refill avoid benchmarking the
  // documented token bucket rather than feed execution. Limits remain enabled.
  await new Promise(resolve=>setTimeout(resolve,3000));
  const feeds=[];let count=0;start=performance.now();
  for(let sample=0;sample<20;sample++){
    let since=0;count=0;const t=performance.now();
    for(;;){const page=await remote.changes({since,limit:100});count+=page.results.length;since=page.last_seq;if(page.results.length<100)break;}
    feeds.push(performance.now()-t);
  }
  assert.ok(count>=255);report(`Complete incremental change poll: ${count} current documents, pages of 100`,feeds,performance.now()-start);
} finally {
  for(const writer of writers)await writer.close();await main.close();await remote.close();
}
// Upstream direct-client watchers can retain timers despite close; all checks above completed.
process.exit(0);
