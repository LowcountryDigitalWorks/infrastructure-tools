"use strict";
/* Synthetic Chromium egress falsification inside a network-none guest.
 * No owner profiles, real websites, accounts, or credentials.
 */
const http = require("node:http");
const net = require("node:net");
const crypto = require("node:crypto");
const { chromium } = require("playwright");
let phase = "INIT";

function fail(reason) {
  process.stdout.write(JSON.stringify({ result: "NO_START", reason }) + "\n");
  process.exitCode = 1;
}

function parseArgs(args) {
  if ((args.length !== 3 && args.length !== 4) || args[0] !== "--probe" ||
      (args.length === 4 && args[3] !== "--trusted-synthetic-only")) throw Error("INVALID_ARGS");
  const host = args[1], port = Number(args[2]);
  if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host) ||
      !Number.isInteger(port) || port < 1 || port > 65535) throw Error("INVALID_TARGET");
  const octets = host.split(".").map(Number);
  if (octets.some(v => v < 0 || v > 255) || host === "127.0.0.1" || host === "0.0.0.0") {
    throw Error("INVALID_TARGET");
  }
  return {host, port, trustedSynthetic:args.length === 4};
}

function directSocketBlocked(host, port) {
  return new Promise(resolve => {
    let socket, done = false;
    function finish(blocked) {
      if (done) return;
      done = true;
      if (socket) socket.destroy();
      resolve(blocked);
    }
    socket = net.connect({ host, port });
    socket.setTimeout(1400);
    socket.once("connect", () => finish(false));
    socket.once("error", () => finish(true));
    socket.once("timeout", () => finish(true));
  });
}

async function main() {
  const {host, port, trustedSynthetic} = parseArgs(process.argv.slice(2));
  const target = "http://" + host + ":" + port;
  let browser = null, server = null;
  try {
    const fixtureHtml = '<!doctype html><title>LDW_SYNTHETIC_BROWSER</title>' +
      '<input id="sample"><button id="action" onclick="document.getElementById(' +
      "'result').textContent=document.getElementById('sample').value" +
      '">Go</button><span id="result"></span>';
    server = http.createServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(200, {"content-type":"text/html","cache-control":"no-store"});
        res.end(fixtureHtml);
      } else if (req.url === "/redirect") {
        res.writeHead(302, {"location": target + "/redirect-target"}); res.end();
      } else if (req.url === "/sw.js") {
        res.writeHead(200, {"content-type":"application/javascript",
                           "service-worker-allowed":"/", "cache-control":"no-store"});
        res.end('self.addEventListener("install",e=>{self.skipWaiting()});' +
          'self.addEventListener("activate",e=>{' +
          'e.waitUntil((async()=>{' +
          'try {await fetch(' + JSON.stringify(target + "/service-worker") +
          ',{mode:"no-cors"})} catch {}' +
          'await self.clients.claim();' +
          '})())})');
      } else { res.writeHead(404); res.end("synthetic-only"); }
    });
    await new Promise((resolve,reject) => {
      server.once("error",reject); server.listen(0,"127.0.0.1",resolve);
    });
    const localPort = server.address().port;
    // Strict mode is always the default. The single explicitly flagged
    // non-sandboxed mode is a TRUSTED SYNTHETIC CI DIAGNOSTIC, never a
    // fallback and never a production/untrusted-page acceptance.
    phase = "BROWSER_LAUNCH";
    browser = await chromium.launch({ headless:true, chromiumSandbox:!trustedSynthetic, timeout:25000 });
    const context = await browser.newContext({ acceptDownloads:false, serviceWorkers:"allow" });
    const page = await context.newPage();
    phase = "LOCAL_NAVIGATION";
    await page.goto("http://127.0.0.1:" + localPort + "/start",
                    {waitUntil:"domcontentloaded", timeout:10000});
    if (await page.title() !== "LDW_SYNTHETIC_BROWSER") throw Error("LOCAL_BROWSER_NAVIGATION");
    phase = "LOCAL_ACTIONS";
    await page.locator("#sample").fill("LDW_OK");
    await page.locator("#action").click();
    if (await page.locator("#result").textContent() !== "LDW_OK") throw Error("LOCAL_INTERACTION");
    const digest = crypto.createHash("sha256").update(await page.screenshot()).digest("hex");
    if (!/^[0-9a-f]{64}$/.test(digest)) throw Error("SCREENSHOT");
    // Generate actual Chromium-originated operations, not Playwright route mocks.
    phase = "PAGE_VECTOR";
    const methods = await page.evaluate(({host,port}) => {
      const t = "http://" + host + ":" + port;
      const attempts = [];
      try { navigator.sendBeacon(t + "/beacon", "LDW_SYNTHETIC"); attempts.push("beacon"); } catch {}
      try { fetch(t + "/keepalive", {method:"POST", body:"LDW", mode:"no-cors", keepalive:true}).catch(()=>{}); attempts.push("keepalive"); } catch {}
      try {
        const a=document.createElement("a");
        a.href="http://127.0.0.1:1/nothere"; a.ping=t+"/ping";a.target="_blank";
        document.body.appendChild(a);a.click();attempts.push("ping");
      } catch {}
      try {
        const ws=new WebSocket("ws://" + host + ":" + port + "/websocket");
        ws.onerror=()=>{};attempts.push("websocket");
      } catch {}
      try {
        const im=document.createElement("img");im.src=t+"/image";
        document.body.appendChild(im);attempts.push("resource");
      } catch {}
      return attempts;
    }, {host,port});
    const mustAttempt = ["beacon","keepalive","ping","websocket","resource"];
    if (mustAttempt.some(x=>!methods.includes(x))) throw Error("BROWSER_VECTOR_NOT_INVOKED");
    // A real Service Worker can evade in-page HTTP routing.
    phase = "SERVICE_WORKER";
    const sw = await page.evaluate(async () => {
      if (!("serviceWorker" in navigator)) return false;
      try {
        const reg=await navigator.serviceWorker.register("/sw.js");
        await navigator.serviceWorker.ready;
        await reg.update();return true;
      } catch {return false;}
    });
    if (!sw) throw Error("SERVICE_WORKER_NOT_INVOKED");
    phase = "REDIRECT";
    let redirectFailed = false;
    try {await page.goto("http://127.0.0.1:" + localPort + "/redirect",
                         {waitUntil:"domcontentloaded",timeout:5000});}
    catch {redirectFailed=true;}
    if (!redirectFailed) throw Error("OFF_GUEST_REDIRECT_WAS_ALLOWED");
    phase = "DIRECT_TCP";
    if (!(await directSocketBlocked(host,port))) throw Error("DIRECT_TCP_REACHED_HOST");
    await new Promise(resolve=>setTimeout(resolve,1000));
    process.stdout.write(JSON.stringify({
      result:"PASS", local_chromium:"PASS", interactions:"PASS",
      vectors:mustAttempt.concat(["service_worker","redirect","direct_tcp"]),
      redirect:"BLOCKED", direct_tcp:"BLOCKED",
      sandbox_requested:!trustedSynthetic,
      source:trustedSynthetic ? "TRUSTED_SYNTHETIC_NO_CHROMIUM_SANDBOX" : "SYNTHETIC_GUEST_ONLY"
    }) + "\n");
  } finally {
    if (browser) await browser.close().catch(()=>{});
    if (server) await new Promise(resolve=>server.close(resolve));
  }
}
const timer=setTimeout(()=>{fail("GUEST_WATCHDOG");process.exit(1)},55000);
main().catch(err=>{
  const known = new Set(["INVALID_ARGS","INVALID_TARGET","LOCAL_BROWSER_NAVIGATION",
    "LOCAL_INTERACTION","SCREENSHOT","BROWSER_VECTOR_NOT_INVOKED",
    "SERVICE_WORKER_NOT_INVOKED","OFF_GUEST_REDIRECT_WAS_ALLOWED","DIRECT_TCP_REACHED_HOST"]);
  fail(known.has(err.message)?err.message:"GUEST_" + phase + "_ERROR");
}).finally(()=>clearTimeout(timer));
