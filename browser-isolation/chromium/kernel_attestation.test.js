"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {parseStatus, evaluate, VALID} = require("./kernel_attestation");

const self = Object.freeze({
  filters:2, ns:{user:"user:[1]",pid:"pid:[2]",net:"net:[3]"}
});
function renderer() {
  return {status:{seccomp:2,filters:3,noNewPrivs:1},
          ns:{user:"user:[4]",pid:"pid:[5]",net:"net:[6]"}};
}
test("strict renderer kernel correlation requires all separate namespaces and added filter",()=>{
  assert.equal(evaluate(self,[renderer()]),"RENDERER_KERNEL_CORROBORATED");
  assert.equal(evaluate(self,[renderer(),renderer()]),"RENDERER_KERNEL_CORROBORATED");
  assert.equal(evaluate(self,[]),"RENDERER_NOT_FOUND");
  assert.equal(evaluate({...self,filters:null},[renderer()]),"KERNEL_STATUS_UNAVAILABLE");
});
test("shared namespaces, missing security filter, inherited-only filter fail closed",()=>{
  for(const [field,code] of [
    ["user","RENDERER_USER_NS_SHARED"],
    ["pid","RENDERER_PID_NS_SHARED"],
    ["net","RENDERER_NET_NS_SHARED"],
  ]){
    const r=renderer();r.ns[field]=self.ns[field];
    assert.equal(evaluate(self,[r]),code);
  }
  let r=renderer();r.status.seccomp=0;
  assert.equal(evaluate(self,[r]),"RENDERER_SECCOMP_NOT_FILTERED");
  r=renderer();r.status.filters=self.filters;
  assert.equal(evaluate(self,[r]),"RENDERER_SECCOMP_NOT_ADDITIONAL");
  r=renderer();r.status.noNewPrivs=0;
  assert.equal(evaluate(self,[r]),"RENDERER_NNP_NOT_SET");
  r=renderer();r.ns=undefined;
  assert.equal(evaluate(self,[r]),"RENDERER_PROCESS_AMBIGUOUS");
  assert.equal(evaluate(self,[renderer(),r]),"RENDERER_PROCESS_AMBIGUOUS");
});
test("read-only status parser accepts kernel fields but rejects overlong text",()=>{
  assert.deepEqual(parseStatus("Name:\tchrome\nSeccomp:\t2\nSeccomp_filters:\t3\nNoNewPrivs:\t1\n"),{
    seccomp:2,filters:3,noNewPrivs:1
  });
  assert.equal(parseStatus("x".repeat(20000)),null);
  assert.equal(parseStatus(null),null);
});
test("all attestation results are bounded fixed codes",()=>{
  for(const code of [
    evaluate(self,[renderer()]), evaluate(self,[]),
    evaluate(self,[{status:{},ns:{user:self.ns.user}}]),
  ]) assert.ok(VALID.has(code));
});
