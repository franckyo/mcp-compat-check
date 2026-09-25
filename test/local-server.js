// Local stand-in for Netlify: serves public/ and routes POST /api/check to the real function handler.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { handler } from "../netlify/functions/check.js";
const root = new URL("../public/", import.meta.url).pathname;
http.createServer(async (req, res) => {
  if (req.url === "/api/check") {
    let body = ""; for await (const c of req) body += c;
    const r = await handler({ httpMethod: req.method, headers: { "x-nf-client-connection-ip": "127.0.0.1" }, body });
    res.writeHead(r.statusCode, r.headers); return res.end(r.body);
  }
  const f = path.join(root, req.url === "/" ? "index.html" : req.url);
  if (!f.startsWith(root) || !fs.existsSync(f)) { res.writeHead(404); return res.end("not found"); }
  res.writeHead(200, { "Content-Type": f.endsWith(".html") ? "text/html" : "text/plain" }); fs.createReadStream(f).pipe(res);
}).listen(8788, () => console.log("http://localhost:8788"));
