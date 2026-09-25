# MCP Compatibility Check

Check **your own** MCP server the way Claude, Cursor and ChatGPT connect to it, and get the results in plain language.

```
npx mcp-compat-check https://mcp.yourcompany.com/mcp
```

What it checks:
- **Spec 2026-07-28:** `server/discover`, with fallback to the older `initialize` handshake
- **Protocol negotiation:** the version agreed, and whether newer versions are rejected instead of negotiated
- **OAuth sign-in:** the discovery documents clients read (WWW-Authenticate, protected-resource metadata and the
  resource-URL match Cursor enforces, authorization-server metadata, PKCE S256, CIMD / DCR registration)
- **Tools:** JSON Schema validity (2020-12), object input schemas, output schemas, names, duplicates
- **Sessions:** servers that reject their own `Mcp-Session-Id`

What it never does: call tools, send credentials, change data, follow redirects, or connect to private/internal
addresses (every DNS answer is checked at connect time).

Add `--json` for machine-readable output (useful in CI). Requires Node.js 20+. Run it only on servers you own or operate.

Page: https://franckyo.github.io/mcp-compat-check/

**Want the problems fixed?** I fix MCP servers for a fixed price agreed up front (spec upgrades, OAuth for Claude/ChatGPT
connectors, broken tools, SDK migrations): franckelsond@gmail.com
