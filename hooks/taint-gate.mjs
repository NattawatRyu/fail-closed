#!/usr/bin/env node
// One script, two events.
//   PostToolUse: if the call brought in stranger-written text, mark the session.
//   PreToolUse:  if the session is marked and the call can act, answer "ask".
//
// It never answers "allow". The worst this hook can do is add a prompt; it
// cannot remove one that Claude Code would otherwise have shown.
import { realpathSync } from "node:fs";
import path from "node:path";
import { taintReason, gateDecision } from "../src/policy.mjs";
import { emit, loadConfig, markTainted, readStdinJson, taintRecord } from "../src/io.mjs";

function ask(reason) {
  emit({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: reason,
    },
  });
}

let input;
try {
  input = readStdinJson();
} catch {
  // Cannot tell which event this is. Answering "ask" on a PostToolUse is
  // ignored by Claude Code, and on a PreToolUse it is the safe answer.
  ask("fail-closed: hook input unreadable - asking instead of guessing");
  process.exit(0);
}

const event = input.hook_event_name;
const tool = input.tool_name ?? "";

try {
  const cfg = loadConfig();
  if (event === "PostToolUse") {
    const cwd = input.cwd ?? process.cwd();
    const roots = [process.env.CLAUDE_PROJECT_DIR ?? cwd, ...(cfg.trustedRoots ?? [])].map((r) => path.resolve(r));
    const reason = taintReason(tool, input.tool_input, {
      cwd,
      trustedRoots: roots.map((r) => { try { return realpathSync(r); } catch { return r; } }),
      untrustedSubpaths: cfg.untrustedSubpaths,
      trustedTools: cfg.trustedTools,
      resolve: (p) => {
        const abs = path.resolve(cwd, p);
        try {
          return realpathSync(abs);
        } catch (e) {
          // A path that does not exist returned no content, so where it would
          // have pointed does not matter. Anything else: refuse to judge.
          if (e.code === "ENOENT") return abs;
          throw e;
        }
      },
    });
    if (reason) markTainted(input.session_id, reason);
  } else if (event === "PreToolUse") {
    const record = taintRecord(input.session_id);
    if (gateDecision(tool, record !== null, cfg) === "ask") {
      ask(
        `fail-closed: this session has read text someone else wrote, so ${tool} needs your OK.\n` +
          `First untrusted input: ${record}`,
      );
    }
  }
} catch (e) {
  if (event === "PreToolUse") ask(`fail-closed: ${e.message} - asking instead of guessing`);
  else process.stderr.write(`fail-closed: ${e.message}\n`);
}
