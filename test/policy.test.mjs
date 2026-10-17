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

test("a single file can be a trusted root, and only that file", () => {
  const settings = path.resolve("/home/me/.claude/settings.json");
  const c = ctx({ trustedRoots: [ROOT, settings] });
  assert.equal(taintReason("Read", { file_path: settings }, c), null);
  assert.match(taintReason("Read", { file_path: path.resolve("/home/me/.claude/settings.json.bak") }, c), /outside/);
  assert.match(taintReason("Read", { file_path: path.resolve("/home/me/.claude/plugins/x/README.md") }, c), /outside/);
});

const PROJECTS = path.resolve("/home/me/.claude/projects");
const CLAUDE_HOME = path.dirname(PROJECTS);
const tctx = (over = {}) => ctx({ trustedRoots: [ROOT, CLAUDE_HOME], untrustedPaths: [`${PROJECTS}/**/*.jsonl`], ...over });

test("untrustedPaths: a transcript inside a trusted root taints; memory beside it does not", () => {
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "p", "abc.jsonl") }, tctx()), /untrusted/);
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "p", "abc", "subagents", "x.jsonl") }, tctx()), /untrusted/);
  assert.equal(taintReason("Read", { file_path: path.join(PROJECTS, "p", "memory", "MEMORY.md") }, tctx()), null);
  assert.equal(taintReason("Read", { file_path: path.join(CLAUDE_HOME, "settings.json") }, tctx()), null);
});

test("untrustedPaths: matched in any case, and ** also matches zero directories", () => {
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "P", "ABC.JSONL") }, tctx()), /untrusted/);
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "top.jsonl") }, tctx()), /untrusted/);
});

test("untrustedPaths: * and ? stay inside one directory; dots are literal", () => {
  const c = tctx({ untrustedPaths: [`${PROJECTS}/*.jsonl`, `${PROJECTS}/log?.txt`] });
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "a.jsonl") }, c), /untrusted/);
  assert.equal(taintReason("Read", { file_path: path.join(PROJECTS, "p", "a.jsonl") }, c), null);
  assert.match(taintReason("Read", { file_path: path.join(PROJECTS, "log1.txt") }, c), /untrusted/);
  assert.equal(taintReason("Read", { file_path: path.join(PROJECTS, "log12.txt") }, c), null);
  assert.equal(taintReason("Read", { file_path: path.join(PROJECTS, "axjsonl") }, c), null);
});

test("untrustedPaths: a search over a directory that holds them taints - at, above and below the base", () => {
  for (const dir of [PROJECTS, CLAUDE_HOME, path.join(PROJECTS, "p")]) {
    assert.match(taintReason("Grep", { path: dir, pattern: "x" }, tctx()), /untrusted/, dir);
    assert.match(taintReason("Glob", { path: dir, pattern: "*" }, tctx()), /untrusted/, dir);
  }
});

test("untrustedPaths: a search elsewhere, or a sibling sharing the base's prefix, does not", () => {
  assert.equal(taintReason("Grep", { path: ROOT, pattern: "x" }, tctx()), null);
  assert.equal(taintReason("Grep", { path: `${PROJECTS}-old`, pattern: "x" }, tctx({ trustedRoots: [ROOT, CLAUDE_HOME] })), null);
});

test("untrustedPaths: a symlink is judged by where it lands", () => {
  const resolve = (p) => (p.endsWith("link") ? path.join(PROJECTS, "p", "abc.jsonl") : path.resolve(ROOT, p));
  assert.match(taintReason("Read", { file_path: "link" }, tctx({ resolve })), /untrusted/);
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

const writeCtx = (file_path, over = {}) => ctx({ input: { file_path }, ...over });

test("gate: a tainted session keeps editing its own project", () => {
  for (const t of ["Edit", "MultiEdit", "Write"]) assert.equal(gateDecision(t, true, writeCtx("src/a.ts")), null, t);
  assert.equal(gateDecision("NotebookEdit", true, ctx({ input: { notebook_path: "nb.ipynb" } })), null);
  assert.equal(gateDecision("Write", true, writeCtx("src/new/deep/file.ts")), null);
});

test("gate: a tainted write outside the roots asks - sibling prefix, .., absolute", () => {
  for (const p of [path.resolve("/work/proj-evil/x"), "../other/x", path.resolve("/home/me/.bashrc")]) {
    assert.equal(gateDecision("Write", true, writeCtx(p)), "ask", p);
  }
});

test("gate: a tainted write into a control path asks, at any depth and any case", () => {
  for (const p of [".claude/settings.json", ".git/hooks/pre-commit", "CLAUDE.md", "docs/claude.md",
    ".Claude/settings.local.json", ".mcp.json", ".github/workflows/ci.yml", ".vscode/tasks.json",
    ".husky/pre-commit", ".envrc", "AGENTS.md", "node_modules/pkg/index.js",
    ".claude./settings.json", ".claude /settings.json", "docs/CLAUDE.md.", "CLAUDE.md. . "]) {
    assert.equal(gateDecision("Edit", true, writeCtx(p)), "ask", p);
  }
});

test("gate: a control path above the root still counts (memory under ~/.claude)", () => {
  const mem = path.resolve("/home/me/.claude/projects/p/memory");
  assert.equal(gateDecision("Write", true, writeCtx(path.join(mem, "MEMORY.md"), { trustedRoots: [ROOT, mem] })), "ask");
});

test("gate: names that only contain a control word do not ask", () => {
  for (const p of ["src/.github-badge.svg", "docs/claude.md.bak", "src/git.ts", "my.vscode.txt"]) {
    assert.equal(gateDecision("Write", true, writeCtx(p)), null, p);
  }
});

test("gate: a tainted write that lands outside through a symlink asks", () => {
  const resolve = (p) => (p.startsWith("linked") ? path.resolve("/home/me/Downloads", p) : path.resolve(ROOT, p));
  assert.equal(gateDecision("Write", true, writeCtx("linked/new.ts", { resolve })), "ask");
});

test("gate: a tainted write it cannot judge asks", () => {
  const resolve = () => { throw new Error("EACCES"); };
  assert.equal(gateDecision("Write", true, writeCtx("src/a.ts", { resolve })), "ask");
  assert.equal(gateDecision("Write", true, ctx({ input: {} })), "ask");
  assert.equal(gateDecision("Write", true, ctx({ input: { file_path: "" } })), "ask");
  assert.equal(gateDecision("Write", true, { input: { file_path: "src/a.ts" } }), "ask");
  assert.equal(gateDecision("Edit", true), "ask");
});

test("gate: strict restores v0.1 - every tainted write asks", () => {
  assert.equal(gateDecision("Edit", true, writeCtx("src/a.ts", { strict: true })), "ask");
});

test("gate: shells and web calls still ask when tainted, however local they look", () => {
  for (const t of ["Bash", "PowerShell", "WebFetch", "WebSearch", "mcp__mail__send"]) {
    assert.equal(gateDecision(t, true, ctx({ input: { command: "npm test", file_path: "src/a.ts" } })), "ask", t);
  }
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
