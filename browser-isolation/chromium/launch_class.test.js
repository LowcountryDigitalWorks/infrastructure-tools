"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyActualLaunchFailure } = require("./launch_class");

const hostLine = "[77:77:FATAL:zygote_host_impl_linux.cc(240)] ";

test("namespace premature exit beats the filename bucket", () => {
  const raw = hostLine + "Zygote process exited prematurely with exit code 1 (namespace sandbox)";
  assert.equal(classifyActualLaunchFailure(raw),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_PREMATURE_EXIT_NAMESPACE");
});

test("setuid premature exit is a separate phase", () => {
  const raw = hostLine + "Zygote process exited prematurely with exit code 4 (setuid sandbox: clone)";
  assert.equal(classifyActualLaunchFailure(raw),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_PREMATURE_EXIT_SETUID");
});

test("boot and hello gaps stay distinct from a bare filename", () => {
  assert.equal(classifyActualLaunchFailure(hostLine + "Failed to receive boot message from zygote"),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_BOOT_MESSAGE_MISSING");
  assert.equal(classifyActualLaunchFailure(hostLine + "Failed to receive hello message from zygote"),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_HELLO_MESSAGE_MISSING");
  assert.equal(classifyActualLaunchFailure(hostLine + "unrecognized startup note"),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_HOST");
});

test("unknown text, including paths and urls, becomes generic and does not echo", () => {
  const raw = "errno=1 secret /home/runner/.env https://example.invalid --no-sandbox";
  const token = classifyActualLaunchFailure(raw);
  assert.equal(token, "GUEST_BROWSER_LAUNCH_ACTUAL_UNKNOWN");
  assert.equal(token.includes("secret"), false);
  assert.equal(token.includes("/home"), false);
  assert.equal(token.includes("http"), false);
  assert.equal(token.includes("sandbox"), false);
  assert.equal(token.includes("errno"), false);
});

test("a classified token is not a successful start", () => {
  const token = classifyActualLaunchFailure(hostLine + "(namespace sandbox)");
  assert.match(token, /^GUEST_BROWSER_LAUNCH_ACTUAL_[A-Z0-9_]+$/);
  assert.notEqual(token, "PASS");
  assert.equal(JSON.stringify({ result: "NO_START", reason: token }).includes("PASS"), false);
});

test("an unqualified premature exit stays premature, not the filename bucket", () => {
  assert.equal(classifyActualLaunchFailure(hostLine + "Zygote process exited prematurely with exit code 9 (unknown helper)"),
    "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_PREMATURE_EXIT");
});

test("seccomp membership still classifies and does not grant a pass", () => {
  const token = classifyActualLaunchFailure("applying seccomp-bpf filter failed");
  assert.equal(token, "GUEST_BROWSER_LAUNCH_ACTUAL_SECCOMP");
  assert.notEqual(token, "PASS");
});
