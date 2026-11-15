import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {normalizeHostMemory, observeHostMemory, SAMPLE_COUNT, MARKER} from '../observer.mjs';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const mb = 1024 * 1024;
const reading = {capacity:32*1024*mb, availableCapacity:18*1024*mb};

function harness(data = Array(5).fill(reading)) {
  const instants = Array.from({length:data.length+1},(_,i)=>new Date(1794542400000 + i*1000));
  let i=0, t=0, pauses=0;
  return {
    getInfo: async()=>data[i++],
    now:()=>instants[t++],
    pause:async()=>{pauses++},
    get pauses(){return pauses},
  };
}

test('exact local-only ChromeOS host evidence is untrusted and never admits JIT', async()=>{
  const h = harness();
  const out = await observeHostMemory(h);
  assert.equal(out.marker, MARKER);
  assert.equal(out.sample_count, SAMPLE_COUNT);
  assert.equal(h.pauses, SAMPLE_COUNT-1);
  assert.equal(out.host_min_available_mib, 18*1024);
  assert.equal(out.memory_sample_scope, 'CHROMEOS_BROWSER_HOST_PHYSICAL');
  assert.equal(out.classification, 'HOST_REPORTED_NOT_ATTESTED');
  assert.equal(out.capture_elapsed_ms, 5000);
  assert.equal(out.ci_dispatch_authorized, false);
  assert.equal(out.jit_admission_authorized, false);
  assert.equal(out.memory_policy_change_authorized, false);
  assert.equal(out.crostini_guest_corroboration, 'NOT_COLLECTED_BY_THIS_EXTENSION');
  assert.equal(out.nested_guest_peak, 'UNMEASURED');
  assert.ok(!/token|credential|ssh|tailnet|hostname|ip_address/i.test(JSON.stringify(out)));
});

test('strict byte bounds, integer type and capacity consistency',()=>{
  for (const bad of [null, [], {}, {capacity:0,availableCapacity:0},
    {capacity:100,availableCapacity:101}, {capacity:100,availableCapacity:-1},
    {capacity:Infinity,availableCapacity:1}, {capacity:2**49,availableCapacity:1},
    {capacity:100.4,availableCapacity:1}, {capacity:'100',availableCapacity:1},
    {capacity:100,availableCapacity:true}, {capacity:NaN,availableCapacity:0}]) {
    assert.throws(()=>normalizeHostMemory(bad,new Date('2026-11-12T20:00:00Z')), /MEMORY_DATA_INVALID/);
  }
});

test('exact bytes convert to integer MiB without implying host guest equivalence',()=>{
  assert.deepEqual(normalizeHostMemory({capacity:3*mb+20, availableCapacity:2*mb+50},new Date('2026-11-12T20:00:00Z')),
    {observed_at_utc:'2026-11-12T20:00:00.000Z',host_total_mib:3,host_available_mib:2});
});

test('time gaps, backward timestamps, changed host capacity fail closed',async()=>{
  const delayed = harness();
  delayed.now=()=>new Date('2026-11-12T20:00:00Z');
  assert.equal((await observeHostMemory(delayed)).capture_elapsed_ms,0);
  const badClock=harness();
  const badDates=[new Date('2026-11-12T20:00:00Z'),new Date('2026-11-12T19:59:00Z')];
  badClock.now=()=>badDates.shift()||new Date('2026-11-12T20:00:00Z');
  await assert.rejects(observeHostMemory(badClock),/CLOCK_UNRELIABLE/);
  const changed=harness([{...reading}, {...reading,capacity:reading.capacity+mb},reading,reading,reading]);
  await assert.rejects(observeHostMemory(changed),/CAPACITY_CHANGED/);
  const tooLong=harness();
  let n=0;
  tooLong.now=()=>new Date(1794542400000 + 5000*(n++));
  await assert.rejects(observeHostMemory(tooLong),/CLOCK_UNRELIABLE/);
});

test('provider failure does not become a fabricated positive',async()=>{
  await assert.rejects(observeHostMemory({...harness(),getInfo:async()=>{throw Error('BLOCKED_PROVIDER')}}),/BLOCKED_PROVIDER/);
  await assert.rejects(observeHostMemory({getInfo:null}),/OBSERVER_CONFIG_INVALID/);
  await assert.rejects(observeHostMemory(harness(),7),/OBSERVER_CONFIG_INVALID/);
});

test('manifest and popup are read-only, local-only, minimal permission surface',()=>{
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8'));
  assert.equal(manifest.manifest_version,3);
  assert.deepEqual(manifest.permissions,['system.memory']);
  assert.ok(!('host_permissions' in manifest));
  assert.ok(!('background' in manifest));
  assert.ok(!('content_scripts' in manifest));
  assert.ok(!('externally_connectable' in manifest));
  const html=fs.readFileSync(path.join(root,'popup.html'),'utf8');
  assert.match(html, /type="module" src="popup.mjs"/);
  for(const file of ['popup.mjs','observer.mjs']){
    const code=fs.readFileSync(path.join(root,file),'utf8');
    for(const pattern of [/\bfetch\s*\(/,/XMLHttpRequest/,/chrome\.storage/,/chrome\.tabs/,/sendMessage\s*\(/,/localStorage/,/WebSocket/,/eval\s*\(/]){
      assert.doesNotMatch(code,pattern,file+' forbidden code');
    }
  }
});
