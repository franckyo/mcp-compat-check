// Checks ONE MCP server the way a standard client connects to it, and explains each result in plain language.
// Workflow: server/discover (spec 2026-07-28) -> legacy initialize fallback -> tools/list; on 401, the public
// OAuth discovery documents every client reads. Never calls tools. Never sends credentials.
import Ajv2020 from "ajv/dist/2020.js";
import { request, jsonBody, validateUrl } from "./net.js";

const NEW = "2026-07-28";
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26"];
const CLIENT = { name: "mcp-compat-check", version: "0.1" };
const NAME_SPEC = /^[A-Za-z0-9_.-]{1,128}$/;
const ajv = new Ajv2020({ strict: false, validateSchema: false });

const item = (level, id, title, impact, evidence = "") => ({ level, id, title, impact, evidence: String(evidence).slice(0, 600) });

async function rpc(url, method, params, { id, session, proto } = {}) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "Mcp-Method": method };
  if (session) headers["Mcp-Session-Id"] = session;
  if (proto) headers["MCP-Protocol-Version"] = proto;
  const body = { jsonrpc: "2.0", method, ...(params ? { params } : {}), ...(id !== undefined ? { id } : {}) };
  const res = await request(url, { method: "POST", headers, body, wantId: id });
  return { ...res, msg: res.error ? null : jsonBody(res) };
}

function networkFailure(r) {
  const map = {
    dns: ["The server's hostname does not resolve", "No client can reach the server: the domain name has no address."],
    tls: ["TLS / certificate problem", "Clients refuse insecure connections, so nobody can connect until the certificate is fixed."],
    timeout: ["The server did not answer in time", "Clients give up and show a connection error."],
    connect: ["The connection was refused or dropped", "Clients cannot open a connection to the server."],
    blocked: ["Address not allowed", "This checker only tests public servers."],
  };
  const [t, i] = map[r.error] || map.connect;
  return item("fail", `NET_${r.error.toUpperCase()}`, t, i, r.detail);
}

function httpFailure(r, what) {
  const text = r.msg ? JSON.stringify(r.msg) : r.body;
  if (r.status >= 500) return item("fail", "HTTP_5XX", `The server returns an error (HTTP ${r.status}) to ${what}`, "Clients cannot connect; users see a generic connection error.", text);
  if ([404, 405, 410].includes(r.status)) return item("fail", "ENDPOINT_NOT_FOUND", `This URL does not accept MCP requests (HTTP ${r.status})`, "Clients configured with this URL cannot connect. Check that the URL points at the MCP endpoint (often ends in /mcp).", text);
  if (r.status === 403) return item("info", "FORBIDDEN", "The server answered 403 Forbidden", "The request was refused without a login challenge. This can be intended (e.g. an allowlist) but clients cannot tell users how to sign in.", text);
  if (r.msg && r.msg.error) return item("fail", "INIT_ERROR", `The server rejects the standard ${what}`, "Clients cannot finish connecting.", JSON.stringify(r.msg.error));
  if (r.status === 200 && !r.msg) return item("fail", "NOT_MCP", "The URL answers, but not with MCP (JSON-RPC)", "Clients cannot understand the response; it is probably a web page, not the MCP endpoint.", `content-type: ${r.contentType}; ${String(r.body).slice(0, 200)}`);
  return item("fail", "INIT_ERROR", `Unexpected answer to ${what} (HTTP ${r.status})`, "Clients cannot finish connecting.", text);
}

async function getJson(url) {
  const r = await request(url, { headers: { Accept: "application/json" } });
  if (r.error || r.status !== 200) return null;
  try { return JSON.parse(r.body); } catch { return null; }
}

async function oauth(url, wwwAuth, out) {
  const u = new URL(url);
  const path = u.pathname.replace(/\/$/, "");
  const m = /resource_metadata="?([^",\s]+)/.exec(wwwAuth || "");
  const prmUrls = [...new Set([m && m[1], `${u.origin}/.well-known/oauth-protected-resource${path}`, `${u.origin}/.well-known/oauth-protected-resource`].filter(Boolean))];
  let prm = null, prmUrl = null;
  for (const p of prmUrls) { if (p.startsWith("https://") && (prm = await getJson(p))) { prmUrl = p; break; } }
  if (!prm) {
    out.push(item("info", "AUTH_API_KEY", "Login required, without OAuth discovery", "The server asks for credentials but publishes no OAuth metadata, so it works with API keys set by hand. Claude.ai and ChatGPT connectors expect OAuth sign-in and cannot log in on their own.", wwwAuth || "no WWW-Authenticate header"));
    return;
  }
  out.push(item(wwwAuth ? "pass" : "warn", "AUTH_CHALLENGE", wwwAuth ? "401 includes a WWW-Authenticate challenge" : "401 without a WWW-Authenticate header", wwwAuth ? "Clients know how to start signing in." : "Some clients cannot start the sign-in flow without this header (the spec requires it).", wwwAuth));
  const resource = String(prm.resource || "");
  const ok = resource && (resource.replace(/\/$/, "") === url.replace(/\/$/, "") || resource.replace(/\/$/, "") === u.origin);
  out.push(item(ok ? "pass" : "fail", "AUTH_RESOURCE_MATCH", ok ? "OAuth metadata names this server correctly" : "OAuth metadata names a different server",
    ok ? "Clients accept the sign-in metadata." : `Clients such as Cursor reject the sign-in because the metadata says the server is "${resource}", not ${url}. Often a wrong public-URL setting behind a proxy or custom domain.`, `${prmUrl} -> resource: ${resource}`));
  const iss = (prm.authorization_servers || [])[0];
  if (!iss) { out.push(item("fail", "AUTH_NO_AS", "No authorization server listed", "Clients don't know where users should sign in.", prmUrl)); return; }
  let iu;
  try { iu = new URL(iss); if (iu.protocol !== "https:") throw 0; }
  catch { out.push(item("fail", "AUTH_BAD_AS", "The login server address is not a valid https URL", "Clients refuse to sign in against it.", iss)); return; }
  const ip = iu.pathname.replace(/\/$/, "");
  let as = null, asUrl = null;
  for (const a of [...new Set([`${iu.origin}/.well-known/oauth-authorization-server${ip}`, `${iu.origin}/.well-known/openid-configuration${ip}`, `${iss.replace(/\/$/, "")}/.well-known/openid-configuration`])]) {
    if ((as = await getJson(a))) { asUrl = a; break; }
  }
  if (!as) { out.push(item("fail", "AUTH_NO_AS_METADATA", "The login server's metadata can't be found", "Clients cannot find the login and token endpoints, so sign-in fails.", iss)); return; }
  const s256 = (as.code_challenge_methods_supported || []).includes("S256");
  out.push(item(s256 ? "pass" : "fail", "AUTH_PKCE", s256 ? "PKCE (S256) supported" : "PKCE S256 not advertised", s256 ? "Clients can complete the secure sign-in flow." : "MCP clients are required to refuse sign-in when the server doesn't advertise PKCE S256.", `code_challenge_methods_supported: ${JSON.stringify(as.code_challenge_methods_supported)}`));
  const cimd = !!as.client_id_metadata_document_supported, dcr = !!as.registration_endpoint;
  if (!cimd && !dcr) out.push(item("fail", "AUTH_NO_REGISTRATION", "Clients can't register themselves", "Claude.ai, ChatGPT and other connectors need to register automatically. Without Client ID Metadata Documents or Dynamic Client Registration, users need a client ID issued by hand.", asUrl));
  else if (!cimd) out.push(item("warn", "AUTH_DCR_ONLY", "Only Dynamic Client Registration supported", "Works today. The 2026-07-28 spec prefers Client ID Metadata Documents and deprecates DCR, and fixed redirect-URI allowlists on DCR are a common reason new clients get blocked.", `registration_endpoint: ${as.registration_endpoint}`));
  else out.push(item("pass", "AUTH_REGISTRATION", "Client ID Metadata Documents supported", "New clients can register without manual steps.", asUrl));
}

function checkTools(tools, negotiated, out) {
  const names = tools.map((t) => t.name);
  const badSchema = [], notObj = [], badOut = [], badName = [], strict = [];
  for (const t of tools) {
    if (typeof t.name !== "string" || !NAME_SPEC.test(t.name)) badName.push(JSON.stringify(t.name));
    else if (t.name.includes(".") || t.name.length > 64) strict.push(t.name);
    const s = t.inputSchema;
    if (s && typeof s === "object") {
      if (!ajv.validateSchema(s)) badSchema.push(`${t.name}: ${ajv.errorsText(ajv.errors).slice(0, 140)}`);
      if (s.type !== "object" && negotiated < NEW) notObj.push(`${t.name}: type=${JSON.stringify(s.type)}`);
    } else notObj.push(`${t.name}: no inputSchema`);
    if (t.outputSchema && typeof t.outputSchema === "object" && !ajv.validateSchema(t.outputSchema)) badOut.push(`${t.name}: ${ajv.errorsText(ajv.errors).slice(0, 140)}`);
  }
  const dups = [...new Set(names.filter((n, i) => n && names.indexOf(n) !== i))];
  const ex = (a) => `${a.length} of ${tools.length}: ${a.slice(0, 4).join(" | ")}`;
  out.push(badSchema.length ? item("fail", "TOOL_SCHEMA_INVALID", "Some tool input schemas are not valid JSON Schema", "Clients that validate schemas (for example the Claude API) reject these tools, and some reject the whole server.", ex(badSchema))
    : item("pass", "TOOL_SCHEMAS", "All tool input schemas are valid JSON Schema", "Clients can load every tool.", `${tools.length} tools`));
  if (notObj.length) out.push(item("fail", "TOOL_SCHEMA_NOT_OBJECT", "Some tools don't declare an object input schema", "The spec requires an object schema; strict clients drop these tools.", ex(notObj)));
  if (badOut.length) out.push(item("fail", "OUTPUT_SCHEMA_INVALID", "Some output schemas are not valid JSON Schema", "Clients that validate results reject these tools' answers.", ex(badOut)));
  if (badName.length) out.push(item("fail", "TOOL_NAME_INVALID", "Some tool names break the spec's naming rules", "Clients may refuse to register these tools.", ex(badName)));
  if (dups.length) out.push(item("fail", "TOOL_NAME_DUPLICATE", "Duplicate tool names", "Clients can only keep one of each; the others become unreachable.", dups.join(", ")));
  if (strict.length) out.push(item("warn", "TOOL_NAME_STRICT", "Some tool names are long or contain dots", "Allowed by the spec, but clients with stricter naming rules may reject them.", ex(strict)));
}

export async function checkServer(rawUrl) {
  const url = validateUrl(rawUrl).toString();
  const out = [];
  const t0 = Date.now();
  const meta = { "io.modelcontextprotocol/protocolVersion": NEW, "io.modelcontextprotocol/clientInfo": CLIENT, "io.modelcontextprotocol/clientCapabilities": {} };
  const d = await rpc(url, "server/discover", { _meta: meta }, { id: 1, proto: NEW });
  const result = { url, checkedAt: new Date().toISOString(), negotiatedVersion: null, serverInfo: null, toolCount: null, items: out };
  if (d.error) { out.push(networkFailure(d)); return finish(result, t0); }

  if (d.status === 401) {
    out.push(item("info", "AUTH_REQUIRED", "The server requires sign-in", "Normal for servers with user data. Below: whether clients can complete the sign-in on their own.", ""));
    await oauth(url, d.headers["www-authenticate"], out);
    return finish(result, t0);
  }

  let tools = null, negotiated = null, session = null;
  if (d.msg && d.msg.result) {
    negotiated = NEW;
    result.serverInfo = d.msg.result.serverInfo || null;
    out.push(item("pass", "SPEC_2026", "Supports the current MCP spec (2026-07-28)", "Clients that open with the new stateless handshake connect directly.", ""));
    const tl = await rpc(url, "tools/list", { _meta: meta }, { id: 2, proto: NEW });
    if (tl.msg && tl.msg.result) tools = tl.msg.result.tools || [];
    else out.push(item("fail", "TOOLS_LIST_ERROR", "Listing tools fails", "Clients connect but see no tools.", JSON.stringify(tl.msg || tl.body).slice(0, 300)));
  } else {
    const rejected = [];
    let ini = null;
    for (const v of LEGACY) {
      ini = await rpc(url, "initialize", { protocolVersion: v, capabilities: {}, clientInfo: CLIENT }, { id: 10 });
      if (ini.error) { out.push(networkFailure(ini)); return finish(result, t0); }
      if (ini.status === 401) {
        out.push(item("info", "AUTH_REQUIRED", "The server requires sign-in", "Below: whether clients can complete the sign-in on their own.", ""));
        await oauth(url, ini.headers["www-authenticate"], out);
        return finish(result, t0);
      }
      if (ini.msg && ini.msg.result) break;
      if (ini.msg && ini.msg.error && /version/i.test(JSON.stringify(ini.msg.error))) { rejected.push(v); continue; }
      break;
    }
    if (!(ini.msg && ini.msg.result)) { out.push(httpFailure(ini, "initialize request")); return finish(result, t0); }
    const r = ini.msg.result;
    negotiated = r.protocolVersion || null;
    result.serverInfo = r.serverInfo || null;
    session = ini.headers["mcp-session-id"] || null;
    out.push(item("warn", "SPEC_2026", "Doesn't support the current MCP spec (2026-07-28) yet",
      "Clients that start with the new handshake must fall back to the older one. Most do today; clients that open with 2026-07-28 and don't fall back fail to connect.", `server/discover -> HTTP ${d.status}; initialize negotiated ${negotiated}`));
    if (rejected.length) out.push(item("warn", "VERSION_NEGOTIATION", "Rejects newer protocol versions instead of negotiating", "The spec says servers should answer with a version they support; clients on newer versions get an error instead.", `rejected ${rejected.join(", ")}`));
    if (negotiated && negotiated < "2025-06-18") out.push(item("warn", "PROTOCOL_OLD", `Uses an old protocol version (${negotiated})`, "Newer client features (structured tool output, current auth rules) aren't available.", ""));
    const missing = ["protocolVersion", "capabilities", "serverInfo"].filter((k) => !(k in r));
    if (missing.length) out.push(item("warn", "INIT_INCOMPLETE", "The initialize answer is missing required fields", "Strict clients may refuse the connection.", missing.join(", ")));
    await rpc(url, "notifications/initialized", undefined, { session, proto: negotiated });
    const tl = await rpc(url, "tools/list", {}, { id: 11, session, proto: negotiated });
    if (tl.msg && tl.msg.result) tools = tl.msg.result.tools || [];
    else if (r.capabilities && r.capabilities.tools) {
      const text = JSON.stringify(tl.msg || tl.body || "");
      if (session && [400, 404].includes(tl.status) && /session/i.test(text))
        out.push(item("fail", "SESSION_REJECTED", "The server rejects its own session", "Clients connect, then every request fails. Typical of load-balanced deployments without sticky sessions or shared session storage.", text.slice(0, 300)));
      else out.push(item("fail", "TOOLS_LIST_ERROR", "Listing tools fails", "Clients connect but see no tools.", text.slice(0, 300)));
    }
  }
  result.negotiatedVersion = negotiated;
  if (tools) { result.toolCount = tools.length; checkTools(tools, negotiated || "", out); }
  return finish(result, t0);
}

function finish(result, t0) {
  result.durationMs = Date.now() - t0;
  const n = (l) => result.items.filter((i) => i.level === l).length;
  result.summary = { fail: n("fail"), warn: n("warn"), pass: n("pass"), info: n("info") };
  result.verdict = result.summary.fail ? "Problems found that stop clients from working" : result.summary.warn ? "Works today, with risks" : "No problems found";
  return result;
}
