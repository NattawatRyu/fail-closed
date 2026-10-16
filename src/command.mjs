// Does a shell command invoke one of the blocked programs?
//
// Born as a git-only hook after a rule ("the owner runs git themselves") was
// broken four times in three days - the last one by `git status --short` pasted
// onto the END of a long typecheck command. Nobody decided to override the rule;
// git rode along in a chain where nothing was looking. So the match is on the
// program as a COMMAND: at the start, or after any separator.
//
// Anchored that way so the innocent strings stay innocent: .github, digit,
// legit, apps/git-manager, --no-gpg-sign.

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Returns the blocked program the command runs, or null. */
export function blockedProgram(command, programs) {
  if (typeof command !== "string" || !programs?.length) return null;
  for (const name of programs) {
    const re = new RegExp(
      String.raw`(?:^|[;&|(\x60\n]|\$\(|&&|\|\|)\s*(?:sudo\s+|env\s+(?:\S+=\S+\s+)*|[A-Za-z_]\w*=\S*\s+|command\s+|exec\s+|xargs\s+(?:-\S+\s+)*)*` +
        escape(name) + String.raw`(?:\.exe)?(?=\s|$|[;&|)])`,
      "im",
    );
    if (re.test(command)) return name;
  }
  return null;
}
