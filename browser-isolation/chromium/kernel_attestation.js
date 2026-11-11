"use strict";
/**
 * Read-only kernel corroboration for synthetic, network-none Chromium guests.
 * Raw /proc strings, executable paths and process arguments never leave this
 * module. No subprocess, privileged operation, host mount or security change.
 * This is a kernel-correlated indicator, NOT a complete sandbox attestation.
 */
const fs = require("node:fs");

const VALID = new Set([
  "RENDERER_KERNEL_CORROBORATED",
  "RENDERER_NOT_FOUND", "RENDERER_PROCESS_AMBIGUOUS",
  "RENDERER_USER_NS_SHARED", "RENDERER_PID_NS_SHARED", "RENDERER_NET_NS_SHARED",
  "RENDERER_SECCOMP_NOT_FILTERED", "RENDERER_SECCOMP_NOT_ADDITIONAL",
  "RENDERER_NNP_NOT_SET", "KERNEL_STATUS_UNAVAILABLE", "KERNEL_PROCESS_UNREADABLE",
]);

function parseStatus(contents) {
  if (typeof contents !== "string" || contents.length > 16384) return null;
  function number(name) {
    const match = contents.match(new RegExp("^" + name + ":\\s*(\\d+)\\s*$", "m"));
    return match ? Number(match[1]) : null;
  }
  return {
    seccomp: number("Seccomp"),
    filters: number("Seccomp_filters"),
    noNewPrivs: number("NoNewPrivs"),
  };
}

function evaluate(self, renderers) {
  if (!self || !Number.isSafeInteger(self.filters) || self.filters < 1 ||
      !Array.isArray(renderers)) return "KERNEL_STATUS_UNAVAILABLE";
  if (renderers.length === 0) return "RENDERER_NOT_FOUND";
  for (const r of renderers) {
    if (!r || !r.ns || !r.status) return "RENDERER_PROCESS_AMBIGUOUS";
    if (r.ns.user === self.ns.user) return "RENDERER_USER_NS_SHARED";
    if (r.ns.pid === self.ns.pid) return "RENDERER_PID_NS_SHARED";
    if (r.ns.net === self.ns.net) return "RENDERER_NET_NS_SHARED";
    if (r.status.noNewPrivs !== 1) return "RENDERER_NNP_NOT_SET";
    if (r.status.seccomp !== 2) return "RENDERER_SECCOMP_NOT_FILTERED";
    if (!Number.isSafeInteger(r.status.filters) ||
        r.status.filters <= self.filters) return "RENDERER_SECCOMP_NOT_ADDITIONAL";
  }
  return "RENDERER_KERNEL_CORROBORATED";
}

function snapshot(proc, pid) {
  const prefix = proc + "/" + pid;
  const status = parseStatus(fs.readFileSync(prefix + "/status", "utf8"));
  return {
    status,
    ns: Object.fromEntries(["user", "pid", "net"].map(key =>
      [key, fs.readlinkSync(prefix + "/ns/" + key)])),
  };
}

function inspectRendererKernel() {
  try {
    const proc = "/proc";
    const self = snapshot(proc, "self");
    if (!self.status || !self.ns) return "KERNEL_STATUS_UNAVAILABLE";
    const snapshotSelf = { ...self.status, ns:self.ns };
    const pids = fs.readdirSync(proc).filter(name => /^\d{1,7}$/.test(name));
    if (pids.length > 1024) return "KERNEL_STATUS_UNAVAILABLE";
    const renderers = [];
    for (const pid of pids) {
      try {
        // Only the trusted full-Chromium renderer type qualifies; never print
        // or store its command line. All such processes must satisfy checks.
        const exe = fs.readlinkSync(proc + "/" + pid + "/exe");
        if (!exe.endsWith("/chrome")) continue;
        const argv = fs.readFileSync(proc + "/" + pid + "/cmdline", "utf8");
        if (!argv.split(String.fromCharCode(0)).includes("--type=renderer")) continue;
        renderers.push(snapshot(proc,pid));
      } catch (e) {
        if (e && (e.code==="ENOENT" || e.code==="ESRCH")) continue;
        return "KERNEL_PROCESS_UNREADABLE";
      }
    }
    return evaluate(snapshotSelf, renderers);
  } catch { return "KERNEL_STATUS_UNAVAILABLE"; }
}

module.exports = {inspectRendererKernel, parseStatus, evaluate, VALID};
