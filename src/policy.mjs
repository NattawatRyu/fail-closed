// Pure policy: which tool calls put stranger-written text into a session, and
// which calls must stop and ask once that has happened.
//
// Ported from ChibiClaude's tool_policy.ts, where the same idea guards a desktop
// agent with mail access. The rule that survived the port: a tool this file does
// not know about is treated as the dangerous case, never the safe one. Forgetting
// an entry must cost a prompt, not a silent execution.
//
// No I/O in here. Path resolution is passed in so a test can drive it.
import path from "node:path";

/** Claude Code built-ins whose output is the session's own text, not a stranger's. */
export const TRUSTED_TOOLS = new Set([
  "Edit", "MultiEdit", "Write", "NotebookEdit",
  "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
  "AskUserQuestion", "ToolSearch", "Skill",
  "EnterPlanMode", "ExitPlanMode",
  // A subagent's own tool calls go through these same hooks, so whatever it read
  // taints the session at the read, not at the summary it hands back.
  "Agent", "Task",
]);

/** Readers whose output is trusted only when the path is inside a trusted root. */
export const PATH_READERS = new Set(["Read", "Grep", "Glob", "LS", "NotebookRead"]);

/** Shells. Their output is trusted unless the command reaches the network. */
export const SHELLS = new Set(["Bash", "PowerShell"]);

/** Tools that may still run unasked in a tainted session: they read, they do not act. */
export const READ_ONLY = new Set([
  "Read", "Grep", "Glob", "LS", "NotebookRead",
  "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
  "AskUserQuestion", "ToolSearch", "EnterPlanMode", "ExitPlanMode",
]);

/**
 * Shell commands that fetch text from somewhere else. A heuristic, and the
 * known hole in this design: a shell can reach the network in ways no pattern
 * lists. Documented as such in the README rather than pretended away.
 */
const NETWORK_COMMAND =
  /(?:^|[\s;&|(`]|\$\()(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|http|https|xh|aria2c|gh\s+(?:api|issue|pr|release|gist)|git\s+(?:clone|fetch|pull)|npm\s+(?:view|info)|pip\s+download)(?:\.exe)?(?=\s|$)/i;

/** Subdirectories of a trusted root that hold other people's text anyway. */
export const DEFAULT_UNTRUSTED_SUBPATHS = ["node_modules", ".venv", "vendor"];

/** Is `p` inside `root`? Both absolute. Case and drive handling come from path.relative. */
export function isInside(root, p, pathApi = path) {
  const rel = pathApi.relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !pathApi.isAbsolute(rel));
}

/**
 * Does this call put stranger-written text into the session?
 * Returns a short reason string when it does, null when it does not.
 *
 *   ctx.trustedRoots       absolute paths whose files the owner wrote
 *   ctx.untrustedSubpaths  names under a root that are still someone else's
 *   ctx.trustedTools       extra tool names the owner vouches for (user config)
 *   ctx.cwd                where a reader with no path argument looks
 *   ctx.resolve(p)         absolute, symlink-resolved path; may throw
 */
export function taintReason(toolName, input, ctx) {
  input = input ?? {};
  if (TRUSTED_TOOLS.has(toolName) || ctx.trustedTools?.includes(toolName)) return null;

  if (PATH_READERS.has(toolName)) {
    const raw = input.file_path ?? input.notebook_path ?? input.path ?? ctx.cwd;
    if (typeof raw !== "string" || raw === "") return `${toolName}: no readable path - assumed untrusted`;
    let resolved;
    try {
      resolved = ctx.resolve(raw);
    } catch {
      return `${toolName}: cannot resolve ${raw} - assumed untrusted`;
    }
    const root = ctx.trustedRoots.find((r) => isInside(r, resolved));
    if (!root) return `${toolName} outside trusted roots: ${resolved}`;
    const rel = path.relative(root, resolved).split(/[\\/]/);
    const hit = rel.find((seg) => (ctx.untrustedSubpaths ?? DEFAULT_UNTRUSTED_SUBPATHS).includes(seg));
    if (hit) return `${toolName} inside ${hit}/: ${resolved}`;
    return null;
  }

  if (SHELLS.has(toolName)) {
    const cmd = typeof input.command === "string" ? input.command : "";
    return NETWORK_COMMAND.test(cmd) ? `${toolName} reached the network: ${cmd.slice(0, 120)}` : null;
  }

  if (toolName === "WebFetch") return `WebFetch ${input.url ?? ""}`.trim();
  if (toolName === "WebSearch") return `WebSearch ${input.query ?? ""}`.trim();

  // MCP tools and anything this file has never heard of.
  return `${toolName}: unknown output source - assumed untrusted`;
}

/** Must this call stop and ask? Only ever "ask" or null - never "allow". */
export function gateDecision(toolName, tainted, ctx = {}) {
  if (!tainted) return null;
  if (READ_ONLY.has(toolName) || ctx.ungatedTools?.includes(toolName)) return null;
  return "ask";
}
