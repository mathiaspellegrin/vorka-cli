#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { generateKeystores } from "./keystore.js";
import { detectVorkaDrives, requireDetectedUnconfiguredDrive } from "./setup.js";

const MAX_BODY_BYTES = 16 * 1024;
const token = randomBytes(32).toString("hex");
let generating = false;

function securityHeaders(response: ServerResponse, nonce?: string): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'nonce-${nonce ?? "none"}'; script-src 'nonce-${nonce ?? "none"}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  );
}

function json(response: ServerResponse, status: number, body: unknown): void {
  securityHeaders(response);
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  if (request.headers["content-type"] !== "application/json") throw new Error("Expected application/json");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request too large");
    chunks.push(buffer);
  }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid request body");
  return value as Record<string, unknown>;
}

function page(): string {
  const nonce = randomBytes(18).toString("base64");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Set up your Vorka Key</title>
<style nonce="${nonce}">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#080b10;color:#f6f8fb}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0,#17302c 0,transparent 34rem),#080b10;display:grid;place-items:center;padding:24px}.shell{width:min(720px,100%)}.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.mark{width:38px;height:38px;border:2px solid #77f0c4;border-radius:12px;display:grid;place-items:center;color:#77f0c4;font-weight:900}.brand span{font-size:22px;font-weight:750;letter-spacing:.02em}.card{background:rgba(17,22,29,.94);border:1px solid #29313d;border-radius:24px;padding:32px;box-shadow:0 24px 80px #0008}h1{font-size:32px;line-height:1.1;margin:0 0 12px}p{color:#aeb8c5;line-height:1.55}.status{border:1px solid #34404e;border-radius:16px;padding:16px;margin:24px 0;display:flex;gap:14px;align-items:center}.dot{width:12px;height:12px;border-radius:50%;background:#ffbd5b;box-shadow:0 0 16px #ffbd5b88}.dot.ok{background:#77f0c4;box-shadow:0 0 16px #77f0c488}.drive{font-family:ui-monospace,monospace;font-size:13px;color:#d9e1ea;word-break:break-all}label{display:block;font-weight:650;margin:18px 0 8px}input,select{width:100%;border:1px solid #354151;background:#0b1016;color:#f6f8fb;border-radius:12px;padding:13px 14px;font:inherit}input:focus,select:focus{outline:2px solid #77f0c4;border-color:transparent}.hint{font-size:13px;color:#8995a5;margin-top:7px}.actions{display:flex;gap:12px;margin-top:26px}button{border:0;border-radius:12px;padding:13px 18px;font:inherit;font-weight:750;cursor:pointer;background:#77f0c4;color:#062019}button.secondary{background:#222b36;color:#dbe4ed}button:disabled{opacity:.45;cursor:not-allowed}.error{color:#ff8f8f;margin-top:16px}.success{padding:18px;border-radius:16px;background:#102b24;border:1px solid #286c58;margin-top:22px}.address{font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;color:#b9ffe6}.hidden{display:none}.warning{font-size:13px;padding:12px 14px;border-left:3px solid #ffbd5b;background:#201a10;color:#e8cfaa;margin-top:20px}@media(max-width:560px){.card{padding:22px}h1{font-size:27px}.actions{flex-direction:column}}
</style></head><body><main class="shell"><div class="brand"><div class="mark">V</div><span>Vorka</span></div><section class="card">
<h1>Set up your Vorka Key</h1><p>Your keys are created on this computer and written to the encrypted USB. Vorka never receives your passwords or private keys.</p>
<div class="status"><div id="dot" class="dot"></div><div><strong id="statusTitle">Looking for your key…</strong><div id="statusPath" class="drive"></div></div></div>
<div id="setup" class="hidden"><label for="drive">Detected Vorka Key</label><select id="drive"></select>
<label for="auth">Daily-use password</label><input id="auth" type="password" autocomplete="new-password" minlength="8"><div class="hint">Minimum 8 characters; 16+ or a generated password is strongly recommended.</div>
<label for="auth2">Confirm daily-use password</label><input id="auth2" type="password" autocomplete="new-password">
<label for="fallback">Recovery password</label><input id="fallback" type="password" autocomplete="new-password" minlength="8"><div class="hint">Minimum 8 characters. Store it separately; it freezes and recovers your vault.</div>
<label for="fallback2">Confirm recovery password</label><input id="fallback2" type="password" autocomplete="new-password">
<div class="warning">A plain USB signs through this computer. Only configure it on a computer you trust.</div>
<div class="actions"><button id="create">Create encrypted keys</button><button id="refresh" class="secondary">Refresh drives</button></div></div>
<div id="error" class="error hidden"></div><div id="success" class="success hidden"><strong>Your Vorka Key is configured.</strong><p>Operational address</p><div id="authAddress" class="address"></div><p>Recovery address</p><div id="fallbackAddress" class="address"></div><p>Back up the encrypted USB files before depositing meaningful funds. These public addresses are safe to copy.</p></div>
</section></main><script nonce="${nonce}">
const TOKEN=${JSON.stringify(token)};const q=(id)=>document.getElementById(id);let drives=[];
async function api(path,options={}){const r=await fetch(path,{...options,headers:{"X-Vorka-Token":TOKEN,...(options.headers||{})}});const body=await r.json();if(!r.ok)throw new Error(body.error||"Request failed");return body}
function fail(message){q("error").textContent=message;q("error").classList.remove("hidden")}
function esc(value){return String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function refresh(){q("error").classList.add("hidden");try{drives=(await api("/api/drives")).drives;const available=drives.filter(d=>!d.configured&&!d.damaged);q("drive").innerHTML=available.map(d=>"<option value=\""+esc(d.path)+"\">"+esc(d.label)+" — "+esc(d.path)+"</option>").join("");if(available.length){q("dot").classList.add("ok");q("statusTitle").textContent="Vorka Key detected";q("statusPath").textContent=available[0].path;q("setup").classList.remove("hidden")}else{const damaged=drives.find(d=>d.damaged),configured=drives.find(d=>d.configured);q("dot").classList.toggle("ok",!!configured&&!damaged);q("statusTitle").textContent=damaged?"This Vorka Key needs attention":configured?"This Vorka Key is already configured":"No unconfigured Vorka Key detected";q("statusPath").textContent=damaged?(damaged.problem+" — "+damaged.path):configured?configured.path:"Plug in a valid provisioned Vorka USB, then refresh.";q("setup").classList.add("hidden")}}catch(e){fail(e.message)}}
q("refresh").onclick=refresh;q("drive").onchange=()=>q("statusPath").textContent=q("drive").value;
q("create").onclick=async()=>{q("error").classList.add("hidden");const auth=q("auth").value,auth2=q("auth2").value,fallback=q("fallback").value,fallback2=q("fallback2").value;if(auth!==auth2)return fail("Daily-use passwords do not match.");if(fallback!==fallback2)return fail("Recovery passwords do not match.");if(auth===fallback)return fail("The two passwords must be different.");q("create").disabled=true;q("create").textContent="Creating keys…";try{const result=await api("/api/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({drivePath:q("drive").value,authPassword:auth,fallbackPassword:fallback})});q("auth").value=q("auth2").value=q("fallback").value=q("fallback2").value="";q("setup").classList.add("hidden");q("success").classList.remove("hidden");q("authAddress").textContent=result.authAddress;q("fallbackAddress").textContent=result.fallbackAddress;q("statusTitle").textContent="Configuration complete"}catch(e){fail(e.message);q("create").disabled=false;q("create").textContent="Create encrypted keys"}};
refresh();setInterval(()=>{if(q("success").classList.contains("hidden"))refresh()},4000);
</script></body></html>`;
}

function validLocalRequest(request: IncomingMessage): boolean {
  const host = request.headers.host ?? "";
  return /^(127\.0\.0\.1|localhost):\d+$/.test(host) && request.headers["x-vorka-token"] === token;
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const host = request.headers.host ?? "";
    if (!/^(127\.0\.0\.1|localhost):\d+$/.test(host)) return json(response, 403, { error: "Forbidden" });
    if (request.method === "GET" && url.pathname === "/") {
      const html = page();
      const nonce = html.match(/nonce="([^"]+)"/)?.[1];
      securityHeaders(response, nonce);
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(html);
      return;
    }
    if (!validLocalRequest(request)) return json(response, 403, { error: "Forbidden" });
    if (request.method === "GET" && url.pathname === "/api/drives") {
      return json(response, 200, { drives: await detectVorkaDrives() });
    }
    if (request.method === "POST" && url.pathname === "/api/generate") {
      if (generating) return json(response, 409, { error: "Key generation is already running" });
      const body = await readJson(request);
      if (typeof body.drivePath !== "string" || typeof body.authPassword !== "string" || typeof body.fallbackPassword !== "string") {
        return json(response, 400, { error: "Missing setup fields" });
      }
      generating = true;
      try {
        const drivePath = await requireDetectedUnconfiguredDrive(body.drivePath);
        const manifest = await generateKeystores(drivePath, body.authPassword, body.fallbackPassword);
        return json(response, 201, { authAddress: manifest.authAddress, fallbackAddress: manifest.fallbackAddress });
      } finally {
        generating = false;
      }
    }
    return json(response, 404, { error: "Not found" });
  } catch (error) {
    return json(response, 400, { error: error instanceof Error ? error.message : "Setup failed" });
  }
});

function openBrowser(url: string): void {
  if (process.argv.includes("--no-open")) return;
  const command = process.platform === "win32" ? "cmd" : process.platform === "darwin" ? "open" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  const child = spawn(command, args, { detached: true, stdio: "ignore" });
  child.unref();
}

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not start Vorka Setup");
  const url = `http://127.0.0.1:${address.port}/`;
  console.log(`Vorka Setup is running at ${url}`);
  console.log("Close this terminal to stop it.");
  openBrowser(url);
});
