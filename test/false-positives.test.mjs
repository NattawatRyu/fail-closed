// Taints that fired in real sessions on nothing anyone else wrote - each paired
// with the case right next to it that must still taint. Loosening a guard is
// only safe if its edge is pinned on both sides.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { taintReason, gateDecision, onlyTrustedHosts } from "../src/policy.mjs";

const ROOT = path.resolve("/work/proj");
const ctx = (over = {}) => ({ cwd: ROOT, trustedRoots: [ROOT], resolve: (p) => path.resolve(ROOT, p), ...over });
const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

// --- shells and the owner's own dev servers --------------------------------

test("trustedHosts: polling the owner's dev server does not taint", () => {
  const c = ctx({ trustedHosts: LOOPBACK });
  for (const cmd of [
    // The exact command that tainted session d167f523 on 2026-10-19.
    'for($i=0;$i -lt 20;$i++){ try { Invoke-WebRequest http://localhost:5007/ -UseBasicParsing -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep 1 } }',
    "curl -s http://localhost:5055/bot-api/quick",
    'curl -s "http://127.0.0.1:8789/api/health"',
    "curl localhost:3000",
    "curl -s http://[::1]:8787/",
    "(Invoke-WebRequest http://localhost:5007).StatusCode",
    "npm run build && curl -sf http://localhost:4173/ > /dev/null && echo up",
    // The health-check loop from session d6a6e59b, 2026-10-18.
    'for i in $(seq 1 15); do c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4310/api/runs); [ "$c" = 200 ] && break; sleep 1; done',
    "Invoke-WebRequest http://localhost:5007/ -OutFile $null",
  ])assert.equal(taintReason("PowerShell", { command: cmd }, c), null, cmd);
});

test("trustedHosts: off by default - localhost still taints until the owner opts in", () => {
  assert.ok(taintReason("Bash", { command: "curl http://localhost:5055/" }, ctx()));
  assert.ok(taintReason("Bash", { command: "curl http://localhost:5055/" }, ctx({ trustedHosts: [] })));
});

test("trustedHosts: anything that might leave the machine still taints", () => {
  const c = ctx({ trustedHosts: LOOPBACK });
  for (const cmd of [
    "curl https://evil.example",
    "curl evil.example",
    "curl http://localhost:5055/ && curl https://evil.example",
    "curl http://localhost:5055/ evil.example",             // second URL, no scheme
    "curl http://localhost.evil.example/",                  // trusted name as a prefix
    "curl http://localhost@evil.example/",                  // userinfo trick
    "curl http://localhostevil.example/",
    "curl http://evil.example/?next=http://localhost/",     // trusted URL inside another
    "curl --resolve localhost:80:6.6.6.6 http://localhost/", // pins the name elsewhere
    "curl -x evil.example:8080 http://localhost/",          // proxy
    "curl http://localhost/ $URL",                          // a variable can be anything
    "curl http://localhost/ %URL%",
    "curl http://localhost$X/",
    "curl http://localhost/$(curl -s https://evil.example)",
    "Invoke-WebRequest -Uri ($base + '/x')",
    "curl $URL",
    "curl http://localhost:5055/ -o page.html",             // unclear costs a prompt, never a miss
    "curl -w '%{http_code}' http://localhost/ -w x; curl https://evil.example",
    "curl -s -w \"$(curl -s https://evil.example)\" http://localhost/", // a fetch hidden in -w is still seen
    "curl -o /dev/null http://localhost/ -o /dev/null evil.example",
    "git clone http://localhost/repo",                      // git/gh/npm/pip never pass
    "curl http://localhost/; gh api repos/x/y",
  ]) assert.ok(taintReason("Bash", { command: cmd }, c), cmd);
});

test("trustedHosts: a host the owner did not name taints", () => {
  assert.ok(taintReason("Bash", { command: "curl http://127.0.0.1:5055/" }, ctx({ trustedHosts: ["localhost"] })));
  assert.equal(onlyTrustedHosts("npm test", LOOPBACK), false, "no fetch at all is not a trusted fetch");
  assert.equal(onlyTrustedHosts(undefined, LOOPBACK), false);
});

test("trustedHosts: never stops the gate once a session is tainted", () => {
  assert.equal(gateDecision("Bash", true, { trustedHosts: LOOPBACK, input: { command: "curl http://localhost/" } }), "ask");
});

// --- the harness's own tools -------------------------------------------------

test("harness built-ins that touch only the session's own work do not taint", () => {
  for (const t of ["TaskStop", "TaskOutput", "BashOutput", "KillShell", "ScheduleWakeup", "CronCreate", "CronList",
    "PushNotification", "EnterWorktree", "ExitWorktree", "SendFeedback", "ReportFindings"]) {
    assert.equal(taintReason(t, {}, ctx()), null, t);
  }
});

test("tools that carry someone else's text still taint", () => {
  for (const t of ["SendMessage", "ListAgents", "Artifact", "ArtifactComments", "ArtifactData", "RemoteTrigger",
    "LSP", "mcp__mail__read", "SomethingNew"]) {
    assert.match(taintReason(t, {}, ctx()), /unknown output source/, t);
  }
});

test("Monitor is judged like a shell, and with no command it is not trusted", () => {
  assert.equal(taintReason("Monitor", { command: "until test -f done; do sleep 5; done" }, ctx()), null);
  assert.match(taintReason("Monitor", { command: "curl -s https://evil.example/feed" }, ctx()), /network/);
  assert.match(taintReason("Monitor", {}, ctx()), /no command/);
});

test("gate: reading task output stays free when tainted; acting still asks", () => {
  for (const t of ["TaskOutput", "BashOutput", "CronList"]) assert.equal(gateDecision(t, true), null, t);
  for (const t of ["TaskStop", "Monitor", "CronCreate", "ScheduleWakeup", "EnterWorktree"]) assert.equal(gateDecision(t, true), "ask", t);
});

// --- a search pointed at one file -------------------------------------------

const PROJECTS = path.resolve("/home/me/.claude/projects");
const CLAUDE_HOME = path.dirname(PROJECTS);
const MEMORY_FILE = path.join(PROJECTS, "p", "memory", "project_aegis.md");
const tctx = (over = {}) => ctx({ trustedRoots: [ROOT, CLAUDE_HOME], untrustedPaths: [`${PROJECTS}/**/*.jsonl`], ...over });

test("Grep on one memory file does not taint (session f9a74db5, 2026-10-17)", () => {
  const isFile = (p) => p === MEMORY_FILE;
  assert.equal(taintReason("Grep", { path: MEMORY_FILE, pattern: "x" }, tctx({ isFile })), null);
  assert.equal(taintReason("Glob", { path: MEMORY_FILE, pattern: "*" }, tctx({ isFile })), null);
});

test("Grep on one transcript file, or on a directory, still taints", () => {
  const t = path.join(PROJECTS, "p", "abc.jsonl");
  assert.match(taintReason("Grep", { path: t, pattern: "x" }, tctx({ isFile: () => true })), /untrusted/);
  const dir = path.join(PROJECTS, "p", "memory");
  assert.match(taintReason("Grep", { path: dir, pattern: "x" }, tctx({ isFile: () => false })), /untrusted/);
  // No isFile at all: the old, wider rule.
  assert.match(taintReason("Grep", { path: MEMORY_FILE, pattern: "x" }, tctx()), /untrusted/);
});

// --- end to end through the real hook ---------------------------------------

const HOOKS = path.join(import.meta.dirname, "..", "hooks");
const tmp = mkdtempSync(path.join(os.tmpdir(), "fail-closed-fp-"));
const project = path.join(tmp, "proj");
const claudeHome = path.join(tmp, "claude");
const memDir = path.join(claudeHome, "projects", "p", "memory");
mkdirSync(project);
mkdirSync(memDir, { recursive: true });
writeFileSync(path.join(memDir, "note.md"), "mine");
writeFileSync(path.join(claudeHome, "projects", "p", "s.jsonl"), "someone else's page");
const cfgFile = path.join(tmp, "config.json");
writeFileSync(cfgFile, JSON.stringify({
  trustedRoots: [claudeHome],
  trustedHosts: LOOPBACK,
  untrustedPaths: [`${claudeHome.replace(/\\/g, "/")}/projects/**/*.jsonl`],
}));
const stateDir = path.join(tmp, "state");

function post(session, tool, tool_input) {
  const r = spawnSync(process.execPath, [path.join(HOOKS, "taint-gate.mjs")], {
    input: JSON.stringify({ hook_event_name: "PostToolUse", session_id: session, cwd: project, tool_name: tool, tool_input }),
    encoding: "utf8",
    env: { ...process.env, CLAUDE_PROJECT_DIR: project, FAIL_CLOSED_STATE_DIR: stateDir, FAIL_CLOSED_CONFIG: cfgFile },
  });
  assert.equal(r.status, 0, r.stderr);
}
const tainted = (session) => existsSync(path.join(stateDir, session));

test("hook: localhost poll and a one-file grep leave the session clean; the real thing does not", () => {
  post("fp1", "PowerShell", { command: "Invoke-WebRequest http://localhost:5007/ -UseBasicParsing" });
  post("fp1", "Grep", { path: path.join(memDir, "note.md"), pattern: "x" });
  post("fp1", "TaskStop", { task_id: "b1" });
  assert.equal(tainted("fp1"), false);

  post("fp2", "Grep", { path: memDir, pattern: "x" });
  assert.equal(tainted("fp2"), true, "a directory search under the transcripts' base still taints");

  post("fp3", "Bash", { command: "curl -s https://evil.example" });
  assert.equal(tainted("fp3"), true);

  post("fp4", "Grep", { path: path.join(claudeHome, "projects", "p", "s.jsonl"), pattern: "x" });
  assert.equal(tainted("fp4"), true);
});
