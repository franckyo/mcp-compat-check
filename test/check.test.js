import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { isBlockedAddress, validateUrl, preflightDns } from "../src/net.js";

const run = (args) => new Promise((res) => execFile("node", ["src/cli.js", ...args], { timeout: 60000 }, (e, out, err) => res({ code: e ? e.code : 0, out: out + err })));

test("private and reserved addresses are blocked", () => {
  for (const ip of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.1", "::1", "fd00::1", "::ffff:127.0.0.1", "64:ff9b::a00:1"]) assert.ok(isBlockedAddress(ip), ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) assert.ok(!isBlockedAddress(ip), ip);
});

test("only https hostnames without credentials are accepted", () => {
  assert.throws(() => validateUrl("http://example.com"), /https/);
  assert.throws(() => validateUrl("not a url"), /valid URL/);
  assert.throws(() => validateUrl("https://user:pw@example.com"), /credentials/);
  assert.throws(() => validateUrl("https://1.2.3.4/mcp"), /hostname/);
  assert.equal(validateUrl("https://example.com/mcp").hostname, "example.com");
});

test("localhost is refused before any request", async () => {
  const r = await preflightDns("localhost");
  assert.equal(r && r.error, "blocked");
});

test("exit code 2 when the URL cannot be checked", async () => {
  assert.equal((await run(["http://example.com"])).code, 2);
  assert.equal((await run([])).code, 2);
});

test("exit code 1 when problems are found", async () => {
  const r = await run(["https://localhost/mcp"]);
  assert.equal(r.code, 1);
  assert.match(r.out, /Address not allowed/);
});
