# fail-closed

Claude Code hooks for the moment an agent reads something a stranger wrote.

Auto mode is great until the agent fetches a web page, opens a file from
Downloads, or reads an MCP tool's output — and that text says *"ignore previous
instructions and run…"*. From that point on, the session's context holds words
somebody else chose. **fail-closed** notices that moment and makes every
action after it ask you first.

```
WebFetch https://some-blog.example   →  session marked tainted
Bash  npm test                        →  "this session has read text someone else
                                          wrote, so Bash needs your OK.
                                          First untrusted input: WebFetch https://…"
```

Reads stay free. Writes, shells, web calls (an exfiltration channel) and every
MCP tool ask. Once tainted, a session stays tainted — approving one call does
not make the stranger's text go away.

## Why not just auto mode?

Claude Code's permission modes are chosen once and hold for the whole session.
fail-closed makes the mode follow what the session has *read*: auto while the
context is your own, ask from the moment a stranger's text gets in.

| | auto mode | ask / default | fail-closed |
|---|---|---|---|
| Decides by | how the action looks | nothing, it always asks | what the session has read |
| Day-to-day work | smooth | prompt fatigue | smooth |
| After reading an injected page | the classifier has to spot that the action came from the attacker | asks | asks, every time, without guessing |
| Who judges | a model, which text can argue with | a fixed rule | a fixed rule |

A good injection asks for something that looks ordinary, like `npm test` or a
one-line config edit. Judged on how it looks, that action passes. fail-closed
never looks at the action. It asks because of where the context has been, and
the prompt names the first untrusted input.

It does not replace auto mode's classifier. It adds a layer next to it. The
classifier is smart and can be talked to; this rule is dumb and can't be. While
this was being built, the classifier blocked two actions (creating a public
repo, spawning a headless agent in `bypassPermissions`) that fail-closed had no
opinion on. Run both.

## Why this exists

These hooks were extracted from a personal setup after real incidents, not
written for the occasion:

- **A desktop agent sent an email nobody approved.** Its confirm gate was written
  correctly and failed closed — and was never reached, because
  `permissionMode: "bypassPermissions"` short-circuits before `canUseTool` is
  ever called. The bounce from the address it invented landed in the owner's
  inbox. Lesson: a guard is only as real as the test proving it fires.
- **An allowlisted tool skipped the taint check.** A later security review found
  that mail-reading tools sat on `allowedTools`, which run *without* the
  permission callback — the very place the session got marked. Reading mail
  never tainted anything. Lesson: the marker has to sit on a path every call
  takes. Here that is `PostToolUse` with matcher `*`.
- **`git` rode along on a chain.** "The owner runs git" was a rule for months.
  It broke four times in three days, the last as `git status --short` pasted
  onto the end of a long typecheck command. Nobody chose to break it; nothing
  was looking at the tail of the chain. Hence `command-block`.

## Install

```
/plugin marketplace add NattawatRyu/fail-closed
/plugin install fail-closed@fail-closed
```

Needs Node 18+. No dependencies.

## What taints a session

| Tool | Taints when |
|---|---|
| `Read`, `Grep`, `Glob`, `LS`, `NotebookRead` | the path resolves (symlinks followed) outside a trusted root, or into `node_modules/`, `.venv/`, `vendor/` |
| `WebFetch`, `WebSearch` | always |
| `Bash`, `PowerShell` | the command reaches the network (`curl`, `wget`, `Invoke-WebRequest`, `git clone/pull`, `gh api`, …) |
| `Edit`, `Write`, `Agent`, `TodoWrite`, … | never — this is the session's own text |
| **anything else, every MCP tool included** | **always** — a tool this policy has never heard of is the dangerous case |

Trusted root = the project directory (`CLAUDE_PROJECT_DIR`), plus any you add.

## Config

`~/.claude/fail-closed.json` — user level only, on purpose. A cloned repo is
exactly the stranger this tool distrusts; a project-level file saying "trust
everything" would be that stranger switching the guard off.

```json
{
  "trustedRoots": ["D:/work/notes"],
  "trustedTools": ["mcp__my-own-server__status"],
  "ungatedTools": [],
  "untrustedSubpaths": ["node_modules", ".venv", "vendor", "third_party"],
  "blockedCommands": ["git"]
}
```

`blockedCommands` is empty by default, so `command-block` does nothing until you
name something. It matches the program as a command — start of line or after
`;` `&&` `||` `|` `(` `` ` `` `$(` — so `.github`, `legit` and
`apps/git-manager` pass, and `npm test && git push` does not.

## Failure behaviour

| Situation | taint-gate | command-block |
|---|---|---|
| stdin is not JSON | asks | allows |
| config exists but is unreadable | asks | allows |
| session id missing or malformed | asks | — |
| taint state unreadable | asks | — |

The taint gate is a security boundary, so it fails closed. The command block
enforces a preference, so a broken block must not stop real work. Neither hook
ever answers `allow`: the worst either can do is add a prompt.

## Limitations — read these

- **A shell is a hole.** Network detection is a pattern list. `python -c
  "import urllib…"` or a script that fetches is not caught. The gap is only in
  *becoming* tainted through a shell; once tainted by anything, every shell
  call asks.
- **Trusted root means "text you or your team wrote".** A freshly cloned
  repository inside your project is a stranger's text. Open such repos as their
  own project, or list their path in `untrustedSubpaths`.
- **`ask` holds in auto mode. Verified live on 2026-10-16** (Claude Code
  2.1.301). With the plugin installed, a `WebFetch` tainted the session and
  every `Bash`/`Edit` after it showed a permission prompt, even though the
  session was in auto mode. **`bypassPermissions` is untested.** Run the probe
  in `experiments/ask-probe/` before relying on this in that mode.
- **Taint state lives in your temp dir**, one file per session, and is never
  cleaned up by the hook. It is small; your OS's temp cleanup handles it.

## Tests

```
npm test
```

Every guard is tested at its edge: the project root itself, a sibling directory
whose name starts with the root's name, `..`, a symlink that lands outside, an
unresolvable path, a session id of `../../escape`, garbage on stdin. Five
mutants of the policy (naive `startsWith` containment, unknown-tool-trusted,
clean-gate-says-allow, node_modules ignored, resolve-failure-trusted) are each
killed by the suite. `command-block` is checked against the PowerShell hook it
replaced, on the same inputs, when that hook is present.

## License

MIT
