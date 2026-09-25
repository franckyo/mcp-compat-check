// Minimal HTTPS client for the checker, with the safety rules a public tool needs:
// - https only, no redirects followed (a redirect is reported, not chased)
// - every DNS answer is checked at connect time: private, loopback, link-local, CGNAT, multicast
//   and reserved addresses are refused (no probing of internal networks, no DNS-rebinding bypass)
// - hard timeouts and a response size cap
import https from "node:https";
import dns from "node:dns";
import net from "node:net";

export const UA = "mcp-compat-check/0.1 (+https://github.com/franckyo/mcp-compat-check)";
const MAX_BYTES = 2_000_000;

function blockedV4(ip) {
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}

export function isBlockedAddress(ip) {
  if (net.isIPv4(ip)) return blockedV4(ip);
  const v = ip.toLowerCase();
  if (v.startsWith("::ffff:")) return blockedV4(v.slice(7));
  // 64:ff9b:: (NAT64) and 2002:: (6to4) can embed any IPv4 address, private ones included
  return v === "::" || v === "::1" || v.startsWith("64:ff9b:") || v.startsWith("2002:") || v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb") || v.startsWith("ff");
}

function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const bad = addrs.find((a) => isBlockedAddress(a.address));
    if (bad) return cb(Object.assign(new Error(`refused: ${hostname} resolves to a private/reserved address`), { code: "EBLOCKED" }));
    if (options.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

export function validateUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error("Not a valid URL"); }
  if (u.protocol !== "https:") throw new Error("Only https:// URLs can be checked");
  if (u.username || u.password) throw new Error("URLs with credentials are not accepted");
  if (net.isIP(u.hostname.replace(/^\[|\]$/g, ""))) throw new Error("Use the server's hostname, not an IP address");
  return u;
}

// One request. Returns {status, headers, body (string), sse (array of parsed events) | error}.
// For event-stream responses, reading stops once a JSON-RPC message with `wantId` arrives.
export function request(url, { method = "GET", headers = {}, body, wantId, timeoutMs = 15000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let req;
    try { if (new URL(url).protocol !== "https:") throw new Error("not an https:// URL"); }
    catch (e) { return resolve({ error: "connect", detail: e.message, ms: 0 }); }
    req = https.request(url, { method, headers: { "User-Agent": UA, ...headers }, lookup: safeLookup, timeout: timeoutMs }, (res) => {
      const ctype = String(res.headers["content-type"] || "").toLowerCase();
      let buf = "", bytes = 0, done = false;
      const finish = (extra = {}) => {
        if (done) return; done = true; clearTimeout(timer); res.destroy();
        resolve({ status: res.statusCode, headers: res.headers, contentType: ctype, body: buf.slice(0, 20000), ms: Date.now() - started, ...extra });
      };
      const timer = setTimeout(() => finish({ truncated: "timeout while reading" }), timeoutMs);
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        buf += chunk; bytes += chunk.length;
        if (bytes > MAX_BYTES) return finish({ truncated: "size cap" });
        if (wantId !== undefined && ctype.includes("text/event-stream")) {
          const msg = parseSse(buf).find((m) => m && m.id === wantId);
          if (msg) finish({ message: msg });
        }
      });
      res.on("end", () => finish());
      res.on("error", (e) => finish({ error: "read", detail: e.message }));
    });
    req.on("timeout", () => { req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })); });
    req.on("error", (e) => {
      const code = e.code || "";
      const kind = code === "EBLOCKED" ? "blocked" : code === "ENOTFOUND" || code === "EAI_AGAIN" ? "dns"
        : code === "ETIMEDOUT" ? "timeout" : /CERT|SSL|TLS|SELF_SIGNED/.test(code + e.message) ? "tls" : "connect";
      resolve({ error: kind, detail: e.message, ms: Date.now() - started });
    });
    if (body !== undefined) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

export function parseSse(text) {
  const out = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("");
    if (!data) continue;
    try { out.push(JSON.parse(data)); } catch { /* partial or non-JSON event */ }
  }
  return out;
}

export function jsonBody(res) {
  if (res.message) return res.message;
  if (!res.body) return null;
  if (res.contentType.includes("text/event-stream")) return parseSse(res.body).find((m) => m && ("result" in m || "error" in m)) || null;
  try { return JSON.parse(res.body); } catch { return null; }
}
