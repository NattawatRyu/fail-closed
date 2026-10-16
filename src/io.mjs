// The hooks' only contact with the outside: stdin, user config, taint state.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export function readStdinJson() {
  return JSON.parse(readFileSync(0, "utf8"));
}

/**
 * User-level config only: ~/.claude/fail-closed.json.
 *
 * Deliberately NOT read from the project. A cloned repo is exactly the stranger
 * this tool distrusts, and a project-level file saying "trust everything" would
 * be that stranger switching the guard off.
 */
export function loadConfig() {
  const file = process.env.FAIL_CLOSED_CONFIG ?? path.join(os.homedir(), ".claude", "fail-closed.json");
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return {};
    // A config that exists but cannot be read is not an empty config.
    throw new Error(`fail-closed: cannot read ${file}: ${e.message}`);
  }
}

function stateDir() {
  return process.env.FAIL_CLOSED_STATE_DIR ?? path.join(os.tmpdir(), "fail-closed", "taint");
}

function stateFile(sessionId) {
  if (typeof sessionId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) return null;
  return path.join(stateDir(), sessionId);
}

/** Append one taint record. Append-only: a session never becomes untainted. */
export function markTainted(sessionId, reason) {
  const file = stateFile(sessionId);
  if (!file) return;
  mkdirSync(stateDir(), { recursive: true });
  appendFileSync(file, `${new Date().toISOString()} ${reason.replace(/\s+/g, " ")}\n`);
}

/**
 * The first taint record, or null if the session is clean.
 * Anything other than "file does not exist" counts as tainted: a state we
 * cannot read is not evidence of a clean session.
 */
export function taintRecord(sessionId) {
  const file = stateFile(sessionId);
  if (!file) return "session id missing or malformed - assumed tainted";
  try {
    return readFileSync(file, "utf8").split("\n")[0] || "empty taint record";
  } catch (e) {
    if (e.code === "ENOENT") return null;
    return `taint state unreadable (${e.code}) - assumed tainted`;
  }
}

export function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
}
