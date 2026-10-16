import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { taintReason, gateDecision, isInside } from "../src/policy.mjs";

const ROOT = path.resolve("/work/proj");
const ctx = (over = {}) => ({
  cwd: ROOT,
  trustedRoots: [ROOT],
  resolve: (p) => path.resolve(ROOT, p),
  ...over,
});

test("a file inside the project does not taint", () => {
  assert.equal(taintReason("Read", { file_path: path.join(ROOT, "src/a.ts") }, ctx()), null);
});

test("the project root itself does not taint (edge: relative path is empty)", () => {
  assert.equal(taintReason("Grep", { path: ROOT }, ctx()), null);
});

test("a sibling whose name starts with the root's name is outside", () => {
  // /work/proj-evil must not pass a startsWith("/work/proj") check.
  assert.match(taintReason("Read", { file_path: path.resolve("/work/proj-evil/x") }, ctx()), /outside/);
});

test("climbing out with .. is outside", () => {
  assert.match(taintReason("Read", { file_path: "../other/secret.md" }, ctx()), /outside/);
});

test("a reader with no path looks at cwd, which is trusted", () => {
  assert.equal(taintReason("Grep", { pattern: "x" }, ctx()), null);
});

test("a symlink inside the root is judged by where it lands", () => {
  const resolve = (p) => (p.endsWith("link") ? path.resolve("/home/me/Downloads/evil.md") : path.resolve(ROOT, p));
  assert.match(taintReason("Read", { file_path: "link" }, ctx({ resolve })), /outside/);
});

test("a path that cannot be resolved taints", () => {
  const resolve = () => { throw new Error("EACCES"); };
  assert.match(taintReason("Read", { file_path: "x" }, ctx({ resolve })), /cannot resolve/);
});

test("node_modules inside the root is still someone else's text", () => {
  assert.match(taintReason("Read", { file_path: "node_modules/pkg/README.md" }, ctx()), /node_modules/);
});

test("web tools always taint", () => {
  assert.ok(taintReason("WebFetch", { url: "https://x" }, ctx()));
  assert.ok(taintReason("WebSearch", { query: "q" }, ctx()));
});

test("an unknown or MCP tool taints - absent from the table is the dangerous case", () => {
  assert.match(taintReason("mcp__mail__read_emails", {}, ctx()), /unknown/);
  assert.match(taintReason("SomeToolFromNextRelease", {}, ctx()), /unknown/);
});

test("the owner can vouch for a tool in user config", () => {
  assert.equal(taintReason("mcp__mine__status", {}, ctx({ trustedTools: ["mcp__mine__status"] })), null);
});

test("a shell taints only when it reaches the network", () => {
  assert.equal(taintReason("Bash", { command: "npm test" }, ctx()), null);
  assert.equal(taintReason("Bash", { command: "echo curly" }, ctx()), null);
  assert.ok(taintReason("Bash", { command: "npm test && curl -s https://x" }, ctx()));
  assert.ok(taintReason("PowerShell", { command: "Invoke-WebRequest https://x" }, ctx()));
  assert.ok(taintReason("Bash", { command: "x=$(wget -qO- https://x)" }, ctx()));
  assert.ok(taintReason("Bash", { command: "git clone https://x" }, ctx()));
});

test("own writes never taint", () => {
  assert.equal(taintReason("Edit", { file_path: "/anywhere" }, ctx()), null);
  assert.equal(taintReason("Write", { file_path: "/anywhere" }, ctx()), null);
});

test("gate: a clean session never asks", () => {
  for (const t of ["Bash", "Write", "WebFetch", "mcp__x__y"]) assert.equal(gateDecision(t, false), null);
});

test("gate: a tainted session asks for anything that acts, including unknown tools", () => {
  for (const t of ["Bash", "PowerShell", "Write", "Edit", "WebFetch", "WebSearch", "mcp__mail__send", "Unknown"]) {
    assert.equal(gateDecision(t, true), "ask", t);
  }
});

test("gate: a tainted session may still read", () => {
  for (const t of ["Read", "Grep", "Glob", "TodoWrite"]) assert.equal(gateDecision(t, true), null, t);
});

test("gate never answers allow - it can add a prompt, never remove one", () => {
  for (const t of ["Bash", "Read", "Write", "x"]) for (const tainted of [true, false]) {
    assert.notEqual(gateDecision(t, tainted), "allow");
  }
});

test("isInside on Windows ignores case and refuses other drives", () => {
  assert.ok(isInside("D:\\proj", "d:\\PROJ\\a.txt", path.win32));
  assert.ok(!isInside("D:\\proj", "C:\\proj\\a.txt", path.win32));
});
