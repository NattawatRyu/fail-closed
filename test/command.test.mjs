import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { blockedProgram } from "../src/command.mjs";

// Shared with the oracle test below: every case is checked against both.
export const CASES = [
  ["git status", true],
  ["  git status", true],
  ["npx tsc --noEmit && git status --short", true], // the incident: git riding a chain
  ["npm test; git log", true],
  ["npm test || git stash", true],
  ["cat x | git apply", true],
  ["echo $(git rev-parse HEAD)", true],
  ["echo `git rev-parse HEAD`", true],
  ["(cd sub && git pull)", true],
  ["sudo git push", true],
  ["git.exe status", true],
  ["npm test\ngit status", true],
  ["git", true],
  ["GIT_DIR=/elsewhere/.git git status", true], // env prefix without `env`
  ["npm test && GIT_PAGER=cat git log", true],
  ["echo a=b git-manager", false],
  ["ls .github", false],
  ["echo digit legit", false],
  ["cd apps/git-manager && npm test", false],
  ["npm run build -- --no-gpg-sign", false],
  ["gitk", false],
  ["echo 'use git-lfs'", false],
  ["", false],
];

test("blockedProgram on every case", () => {
  for (const [cmd, blocked] of CASES) {
    assert.equal(blockedProgram(cmd, ["git"]), blocked ? "git" : null, JSON.stringify(cmd));
  }
});

test("no configured programs blocks nothing", () => {
  assert.equal(blockedProgram("git status", []), null);
  assert.equal(blockedProgram("git status", undefined), null);
});

test("a program name with regex characters is matched literally", () => {
  assert.equal(blockedProgram("c++ main.cpp", ["c++"]), "c++");
  assert.equal(blockedProgram("cxx main.cpp", ["c++"]), null);
});

// Oracle: the PowerShell hook this replaces, run on the same inputs. Where the
// two disagree, the case list above says which one was right.
const ORACLE = path.join(os.homedir(), ".claude", "hooks", "git-block.ps1");
test("agrees with git-block.ps1 wherever that one was right", { skip: !existsSync(ORACLE) && "oracle not on this machine" }, () => {
  const disagreements = [];
  for (const [cmd, expected] of CASES) {
    if (cmd === "") continue;
    const r = spawnSync("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ORACLE], {
      input: JSON.stringify({ tool_input: { command: cmd } }),
      encoding: "utf8",
    });
    const oldBlocked = r.stdout.includes('"deny"');
    const newBlocked = blockedProgram(cmd, ["git"]) !== null;
    if (oldBlocked !== newBlocked) disagreements.push({ cmd, oldBlocked, newBlocked, expected });
  }
  // Every disagreement must be one where the new code matches the expectation.
  for (const d of disagreements) assert.equal(d.newBlocked, d.expected, `regression vs oracle: ${JSON.stringify(d)}`);
  if (disagreements.length) console.log("improvements over oracle:", disagreements);
});
