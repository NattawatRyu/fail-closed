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
  // Harness built-ins that only touch the session's own work: background tasks
  // it started (their commands were judged when they ran), its own schedule,
  // its own worktrees, notes to the owner.
  "TaskOutput", "BashOutput", "TaskStop", "KillShell",
  "ScheduleWakeup", "CronCreate", "CronDelete", "CronList",
  "PushNotification", "EnterWorktree", "ExitWorktree",
  "SendFeedback", "ReportFindings", "EndConversation",
]);

/** Readers whose output is trusted only when the path is inside a trusted root. */
export const PATH_READERS = new Set(["Read", "Grep", "Glob", "LS", "NotebookRead"]);

/** Shells. Their output is trusted unless the command reaches the network. */
export const SHELLS = new Set(["Bash", "PowerShell"]);

/** Not shells by name, but they run a `command` all the same: judged like one. */
export const COMMAND_RUNNERS = new Set(["Monitor"]);

/** Tools that may still run unasked in a tainted session: they read, they do not act. */
export const READ_ONLY = new Set([
  "Read", "Grep", "Glob", "LS", "NotebookRead",
  "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
  "AskUserQuestion", "ToolSearch", "EnterPlanMode", "ExitPlanMode",
  "TaskOutput", "BashOutput", "CronList",
]);

/**
 * Shell commands that fetch text from somewhere else. A heuristic, and the
 * known hole in this design: a shell can reach the network in ways no pattern
 * lists. Documented as such in the README rather than pretended away.
 */
const FETCHERS = String.raw`curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|http|https|xh|aria2c`;
const NET_TOOLS = String.raw`gh\s+(?:api|issue|pr|release|gist)|git\s+(?:clone|fetch|pull)|npm\s+(?:view|info)|pip\s+download`;
const asCommand = (names) => new RegExp(String.raw`(?:^|[\s;&|(\x60]|\$\()(?:${names})(?:\.exe)?(?=\s|$)`, "i");
const NETWORK_COMMAND = asCommand(`${FETCHERS}|${NET_TOOLS}`);
const URL_FETCHER = asCommand(FETCHERS);
const NETWORK_TOOL = asCommand(NET_TOOLS);

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Does every network call in this command go only to `trustedHosts` - the
 * owner's own dev servers? Each segment that fetches must name a trusted URL,
 * and once that is cut out every word left must be plain: a flag, a bare word,
 * a number. A dotted name, `host:port`, another `://`, a `$var` or `%VAR%` that
 * could expand to a URL - any of those and the command stays tainted.
 * git/gh/npm/pip never pass. `-OutFile page.html` costs a prompt, never a miss.
 */
const PLAIN_WORD = /^(?:-{1,2}[A-Za-z][\w-]*|[A-Za-z][\w-]*|\d+)$/;

export function onlyTrustedHosts(cmd, hosts) {
  if (typeof cmd !== "string" || !hosts?.length) return false;
  const h = hosts.map((x) => reEscape(String(x).toLowerCase())).join("|");
  const url = new RegExp(
    String.raw`(?:(?<=^|[\s"'])|\bhttps?://)(?:${h})(?::\d+)?(?=[/?#\s"']|$)(?:[/?#][^\s"']*)?`,
    "gi",
  );
  // curl's -w format ("%{http_code}") is printed locally; its braces would
  // otherwise split the segment. Kept when it names a fetcher, so it is judged.
  const local = cmd.replace(/(^|\s)(?:-w|--write-out)\s+("[^"]*"|'[^']*'|\S+)/g, (m, pre, v) =>
    NETWORK_COMMAND.test(v) ? m : pre);
  let fetched = false;
  for (const seg of local.split(/[;&|\n(){}\x60]+/)) {
    if (NETWORK_TOOL.test(seg)) return false;
    if (!URL_FETCHER.test(seg)) continue;
    const rest = seg.replace(url, " ");
    if (rest === seg) return false;
    // Throwing the body away is not a fetch from anywhere; any other target is a word to judge.
    const words = rest.replace(/["']/g, " ").replace(/(?:^|\s)(?:\d?>>?|-o|--output|-OutFile)\s*(?:\/dev\/null|\$null|nul)(?=\s|$)/gi, " ").trim().split(/\s+/).filter(Boolean);
    if (!words.every((w) => PLAIN_WORD.test(w))) return false;
    fetched = true;
  }
  return fetched;
}

/** Subdirectories of a trusted root that hold other people's text anyway. */
export const DEFAULT_UNTRUSTED_SUBPATHS = ["node_modules", ".venv", "vendor"];

/** Forward slashes, lower case: one spelling per path on every platform. */
const norm = (p) => p.replace(/\\/g, "/").toLowerCase();

/**
 * A glob as a regex. `**` crosses directories, `*` and `?` do not. Compared
 * case-insensitively everywhere: on Windows and macOS that is the filesystem's
 * own rule, and elsewhere the mismatch can only add a prompt.
 */
function globRegex(glob) {
  let re = "";
  const g = norm(glob);
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*" && g[i + 1] === "*") {
      i++;
      if (g[i + 1] === "/") { i++; re += "(?:.*/)?"; } else re += ".*";
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The part of a glob before its first wildcard segment: where its matches can live. */
function globBase(glob) {
  const segs = norm(glob).split("/");
  const i = segs.findIndex((s) => /[*?]/.test(s));
  return (i === -1 ? segs : segs.slice(0, i)).join("/");
}

const insideNorm = (root, p) => p === root || p.startsWith(root.endsWith("/") ? root : `${root}/`);

/**
 * Which `untrustedPaths` glob does this read reach? A file reader reaches what
 * it names. A searcher (Grep, Glob, LS) may be pointed at a directory, and then
 * it reaches everything under it - so a search whose path is an ancestor of the
 * glob's base, or anywhere under that base, counts too. That last case can ask
 * for a search that would have found no match; it cannot miss one that would.
 */
function untrustedGlobHit(toolName, resolved, globs, isFile) {
  const p = norm(resolved);
  // A search pointed at one file reaches that file and nothing under it.
  const single = toolName === "Read" || toolName === "NotebookRead" || isFile?.(resolved) === true;
  for (const g of globs ?? []) {
    if (globRegex(g).test(p)) return g;
    if (single) continue;
    const base = globBase(g);
    if (insideNorm(p, base) || insideNorm(base, p)) return g;
  }
  return null;
}

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
 *   ctx.untrustedPaths     absolute globs that are someone else's, even inside a root
 *   ctx.trustedTools       extra tool names the owner vouches for (user config)
 *   ctx.cwd                where a reader with no path argument looks
 *   ctx.resolve(p)         absolute, symlink-resolved path; may throw
 *   ctx.isFile(p)          optional: true only when p is a regular file
 *   ctx.trustedHosts       hosts a shell may fetch from without tainting (opt-in)
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
    // Checked before the roots: a trusted root can hold someone else's text,
    // like the transcripts under ~/.claude/projects that quote every web page
    // an earlier session fetched.
    const glob = untrustedGlobHit(toolName, resolved, ctx.untrustedPaths, ctx.isFile);
    if (glob) return `${toolName} reaches untrusted ${glob}: ${resolved}`;
    const root = ctx.trustedRoots.find((r) => isInside(r, resolved));
    if (!root) return `${toolName} outside trusted roots: ${resolved}`;
    const rel = path.relative(root, resolved).split(/[\\/]/);
    const hit = rel.find((seg) => (ctx.untrustedSubpaths ?? DEFAULT_UNTRUSTED_SUBPATHS).includes(seg));
    if (hit) return `${toolName} inside ${hit}/: ${resolved}`;
    return null;
  }

  if (SHELLS.has(toolName) || COMMAND_RUNNERS.has(toolName)) {
    if (COMMAND_RUNNERS.has(toolName) && typeof input.command !== "string") {
      return `${toolName}: no command to judge - assumed untrusted`;
    }
    const cmd = typeof input.command === "string" ? input.command : "";
    if (!NETWORK_COMMAND.test(cmd) || onlyTrustedHosts(cmd, ctx.trustedHosts)) return null;
    return `${toolName} reached the network: ${cmd.slice(0, 120)}`;
  }

  if (toolName === "WebFetch") return `WebFetch ${input.url ?? ""}`.trim();
  if (toolName === "WebSearch") return `WebSearch ${input.query ?? ""}`.trim();

  // MCP tools and anything this file has never heard of.
  return `${toolName}: unknown output source - assumed untrusted`;
}

/** Tools that write one file, and the input key naming it. */
export const WRITERS = new Map([
  ["Edit", "file_path"], ["MultiEdit", "file_path"], ["Write", "file_path"], ["NotebookEdit", "notebook_path"],
]);

/**
 * Names that something runs or loads on its own, later, with no further tool
 * call for this gate to see: git hooks, Claude Code settings and hooks, the next
 * session's instructions, editor tasks, CI with its secrets, direnv. A write
 * there from a tainted session is persistence, not an edit. Matched on any path
 * segment, case-insensitively - Windows and macOS filesystems ignore case, so
 * `.Claude/settings.json` is the same file.
 */
export const DEFAULT_CONTROL_PATHS = [
  ".git", ".claude", ".github", ".husky", ".vscode", ".idea", ".devcontainer",
  ".mcp.json", "claude.md", "claude.local.md", "agents.md", ".envrc", ".npmrc",
];

/**
 * Why a write from a tainted session must ask, or null when it may go ahead:
 * inside a trusted root, outside any control path or vendored directory. A
 * bad edit there is visible in `git diff` and can be undone; the gate keeps its
 * prompts for what cannot.
 */
export function writeRisk(toolName, input, ctx) {
  const raw = input?.[WRITERS.get(toolName)];
  if (typeof raw !== "string" || raw === "") return "no target path";
  if (!ctx.trustedRoots?.length || !ctx.resolve) return "no trusted roots to judge against";
  let resolved;
  try {
    resolved = ctx.resolve(raw);
  } catch {
    return `cannot resolve ${raw}`;
  }
  const root = ctx.trustedRoots.find((r) => isInside(r, resolved));
  if (!root) return `outside trusted roots: ${resolved}`;
  const risky = [...(ctx.controlPaths ?? DEFAULT_CONTROL_PATHS), ...(ctx.untrustedSubpaths ?? DEFAULT_UNTRUSTED_SUBPATHS)]
    .map((s) => s.toLowerCase());
  // The whole path, not just the part below the root: a root may itself sit in
  // one (~/.claude/projects holds the memory every new session loads).
  // Win32 drops trailing dots and spaces, so `.claude.` and `CLAUDE.md ` are the
  // real thing to any program that opens them without a \\?\ prefix.
  const hit = resolved.split(/[\\/]/).find((seg) => risky.includes(seg.toLowerCase().replace(/[. ]+$/, "")));
  return hit ? `${hit} runs or loads without asking: ${resolved}` : null;
}

/**
 * Must this call stop and ask? Only ever "ask" or null - never "allow".
 *
 * Tainted, a session keeps reading and keeps editing its own project. Everything
 * that can carry text out or act beyond the project asks: shells, web calls,
 * MCP tools, unknown tools, and writes outside the roots or into control paths.
 * Shells ask even when they look local: the attacker writes the command, and a
 * pattern list is no match for someone choosing a command to slip past it.
 *
 *   ctx.input   the tool input, needed to judge a write
 *   ctx.strict  true restores v0.1: every write asks
 */
export function gateDecision(toolName, tainted, ctx = {}) {
  if (!tainted) return null;
  if (READ_ONLY.has(toolName) || ctx.ungatedTools?.includes(toolName)) return null;
  if (WRITERS.has(toolName) && !ctx.strict && writeRisk(toolName, ctx.input, ctx) === null) return null;
  return "ask";
}
