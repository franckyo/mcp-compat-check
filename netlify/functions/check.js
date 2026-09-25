// POST /api/check  {"url": "https://...", "owner": true}
// Runs the standard-client compatibility check against ONE server the requester says they own or operate.
import { checkServer } from "../../src/check.js";

const hits = new Map(); // per-instance, best-effort rate limit: 6 checks / 10 min / IP
function limited(ip) {
  const now = Date.now(), win = 10 * 60 * 1000;
  const arr = (hits.get(ip) || []).filter((t) => now - t < win);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 6;
}
const reply = (status, obj) => ({ statusCode: status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }, body: JSON.stringify(obj) });

export async function handler(event) {
  if (event.httpMethod !== "POST") return reply(405, { error: "Use POST" });
  const ip = event.headers["x-nf-client-connection-ip"] || event.headers["x-forwarded-for"] || "unknown";
  if (limited(ip)) return reply(429, { error: "Too many checks from your address. Try again in a few minutes." });
  let input;
  try { input = JSON.parse(event.body || "{}"); } catch { return reply(400, { error: "Invalid request" }); }
  if (input.owner !== true) return reply(400, { error: "Please confirm that you own or operate this server." });
  try {
    return reply(200, await checkServer(String(input.url || "").trim()));
  } catch (e) {
    return reply(400, { error: e.message });
  }
}
