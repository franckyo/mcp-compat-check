#!/usr/bin/env node
// Usage: npx mcp-compat-check https://your-server.example.com/mcp [--json]
import { checkServer } from "./check.js";

const [url, flag] = process.argv.slice(2);
// Exit codes: 0 = no problems (risks allowed), 1 = problems found, 2 = could not check / bad usage
if (!url) { console.error("Usage: mcp-compat-check <https://your-mcp-server/mcp> [--json]"); process.exit(2); }
const icon = { fail: "✖", warn: "!", pass: "✓", info: "i" };
try {
  const r = await checkServer(url);
  const code = r.summary.fail > 0 ? 1 : 0;
  if (flag === "--json") { console.log(JSON.stringify(r, null, 2)); process.exit(code); }
  console.log(`\n${r.url}\n${r.verdict}  (${r.summary.fail} problems, ${r.summary.warn} risks, ${r.summary.pass} passed)`);
  if (r.serverInfo) console.log(`server: ${r.serverInfo.name || "?"} ${r.serverInfo.version || ""} | protocol ${r.negotiatedVersion} | tools ${r.toolCount ?? "-"}`);
  for (const i of r.items) console.log(`\n ${icon[i.level]} ${i.title}\n   ${i.impact}${i.evidence ? `\n   evidence: ${i.evidence}` : ""}`);
  console.log(`\nchecked in ${r.durationMs} ms. Only the standard client handshake was used; no tools were called.`);
  process.exit(code);
} catch (e) { console.error("Cannot check:", e.message); process.exit(2); }
