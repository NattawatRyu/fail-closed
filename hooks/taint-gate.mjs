#!/usr/bin/env node
// One script, two events.
//   PostToolUse: if the call brought in stranger-written text, mark the session.
//   PreToolUse:  if the session is marked and the call can act, answer "ask".
//
// It never answers "allow". The worst this hook can do is add a prompt; it
// cannot remove one that Claude Code would otherwise have shown.
import { realpathSync } from "node:fs";
import path from "node:path";
import { taintReason, gateDecision, writeRisk, WRITERS } from "../src/policy.mjs";
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

const real = (p) => { try { return realpathSync(p); } catch { return p; } };

/**
 * The OS's own name for a path: on Windows this expands 8.3 short names
 * (`.CLAUD~1`), which the JS realpath leaves as typed. Falls back to the JS one
 * where the native call is known to fail on some filesystems.
 */
function canonical(p) {
  try {
    return realpathSync.native(p);
  } catch (e) {
    if (e.code === "ENOENT") throw e;
    return realpathSync(p);
  }
}

/**
 * Absolute, symlink-resolved path for a file that may not exist yet. A new file
 * under a junction inside the project lands wherever the junction points, so
 * resolve the deepest ancestor that exists and re-attach the rest.
 */
function resolveForWrite(abs) {
  let dir = abs;
  const rest = [];
  for (;;) {
    try {
      return path.join(canonical(dir), ...rest);
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      const parent = path.dirname(dir);
      if (parent === dir) throw e;
      rest.unshift(path.basename(dir));
      dir = parent;
    }
  }
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
  const cwd = input.cwd ?? process.cwd();
  const trustedRoots = [process.env.CLAUDE_PROJECT_DIR ?? cwd, ...(cfg.trustedRoots ?? [])]
    .map((r) => real(path.resolve(r)));
  if (event === "PostToolUse") {
    const reason = taintReason(tool, input.tool_input, {
      cwd,
      trustedRoots,
      untrustedSubpaths: cfg.untrustedSubpaths,
      untrustedPaths: cfg.untrustedPaths,
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
    else if (WRITERS.has(tool) && taintRecord(input.session_id) !== null) {
      // Edits made after the taint went through unasked. Keep a list, so the
      // owner knows which files to read in `git diff` before running them.
      const target = input.tool_input?.[WRITERS.get(tool)];
      markTainted(input.session_id, `${tool} wrote ${target} while tainted`);
    }
  } else if (event === "PreToolUse") {
    const record = taintRecord(input.session_id);
    const ctx = {
      ...cfg,
      input: input.tool_input,
      trustedRoots,
      resolve: (p) => resolveForWrite(path.resolve(cwd, p)),
    };
    if (gateDecision(tool, record !== null, ctx) === "ask") {
      const why = WRITERS.has(tool) && !cfg.strict ? `\nThis write asks because: ${writeRisk(tool, input.tool_input, ctx)}` : "";
      ask(
        `fail-closed: this session has read text someone else wrote, so ${tool} needs your OK.\n` +
          `First untrusted input: ${record}${why}`,
      );
    }
  }
} catch (e) {
  if (event === "PreToolUse") ask(`fail-closed: ${e.message} - asking instead of guessing`);
  else process.stderr.write(`fail-closed: ${e.message}\n`);
}
