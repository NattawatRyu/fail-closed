// Probe: does a PreToolUse "ask" survive each permission mode?
// Logs that it fired, then answers "ask" for every Bash call.
import { appendFileSync, readFileSync } from "node:fs";

const input = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(new URL("./fired.log", import.meta.url), `${input.permission_mode ?? "?"} ${input.tool_name}\n`);
process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "ask",
    permissionDecisionReason: "probe: ask",
  },
}));
