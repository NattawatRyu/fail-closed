#!/usr/bin/env node
// PreToolUse on Bash/PowerShell: deny commands that run a blocked program.
// Configure in ~/.claude/fail-closed.json: { "blockedCommands": ["git"] }.
//
// The escape hatch is the owner's own prompt: `! git status` runs in their
// shell and never reaches a tool. There is deliberately no in-band override -
// anything the model can type, the model can be talked into typing.
import { blockedProgram } from "../src/command.mjs";
import { emit, loadConfig, readStdinJson } from "../src/io.mjs";

let input, cfg;
try {
  input = readStdinJson();
  cfg = loadConfig();
} catch {
  // This guard enforces a preference, not a security boundary; a block that
  // cannot read its input must not stop real work. The taint gate is the one
  // that fails closed.
  process.exit(0);
}

const hit = blockedProgram(input.tool_input?.command, cfg.blockedCommands);
if (hit) {
  emit({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason:
        `Blocked: this command runs \`${hit}\`, which the owner runs themselves.\n` +
        `This fires on a chained command too - ${hit} pasted onto the end of another command is still ${hit}.\n` +
        `If it needs running, ask the owner to type it with the ! prefix (e.g. ! ${hit} ...).`,
    },
  });
}
