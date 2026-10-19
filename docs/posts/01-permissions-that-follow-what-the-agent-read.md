---
title: Your AI agent's permissions should follow what it has read
published: false
tags: ai, security, claudecode, llm
canonical_url: https://github.com/NattawatRyu/fail-closed
---

# Your AI agent's permissions should follow what it has read

Claude Code makes you pick a permission mode at the start of a session, and
that choice holds until the session ends. Pick *ask* and every shell command
waits for you. Pick *auto* and the agent runs to completion while a
classifier screens each action.

Neither choice changes when the session's context changes. Yet that is the one
change that matters for security. At 10:00 the context holds only your prompt
and your code. At 10:05 the agent fetches a blog post to check an API, and from
then on the context holds words a stranger chose. If those words say *"run
this to finish the setup"*, the agent's next action may come from the stranger,
not from you. The mode stays the same either way.

I built [fail-closed](https://github.com/NattawatRyu/fail-closed), a small
Claude Code plugin, so the mode would follow what the session has read.

## The idea: taint, then gate what cannot be undone

Two hooks do the work.

**A `PostToolUse` hook with matcher `*` marks the session tainted** the moment a
tool returns text from outside your trust boundary:

- `WebFetch` and `WebSearch`, always
- `Read`/`Grep`/`Glob` on a path outside your project, or inside
  `node_modules/`, `.venv/` or `vendor/`
- a shell command that reaches the network (`curl`, `git clone`, `gh api`, …)
- **every MCP tool and every tool the policy has never heard of**, since an
  unknown tool is the dangerous case, not the safe one

Once tainted, a session stays tainted. Approving one call does not take the
stranger's text out of the context.

**A `PreToolUse` hook then gates actions by whether they can be undone.** In a
tainted session:

| Action | Result |
|---|---|
| Read, Grep, Glob | goes ahead (reading does not act) |
| Edit/Write inside the project | goes ahead, and the path is logged |
| Write into `.git/`, `.claude/`, `.github/`, `CLAUDE.md`, `.npmrc`, … | **asks** |
| Write outside the project | **asks** |
| Bash, PowerShell, WebFetch, any MCP tool | **asks** |

The prompt names the reason: *"this session has read text someone else wrote.
First untrusted input: WebFetch https://…"*

## Why the line is reversibility

The first version asked for *everything* once the session was tainted. It was
unusable. One `Read` of a harness-owned JSON file outside the project tainted a
session, and every edit after it asked until the session ended. In practice
that gets you clicking "yes" without reading the prompt, and a gate you approve
by reflex is worse than no gate, because it still feels safe.

A security gate spends the user's attention, and attention runs out. So v0.2
asks only about actions that cannot be taken back:

- **A bad edit to `src/`** shows up in `git diff` and reverts. That is fine.
- **Data sent over the network** does not come back.
- **A write to a control path** runs later by itself: a git hook on the next
  commit, a Claude Code hook on the next tool call, `CLAUDE.md` in the next
  session's system prompt. No later tool call goes through the gate, so the
  gate has to stop it here.

The edits it lets through are appended to the taint record, which gives you a
list of files to read in `git diff` before you run anything.

Control paths are matched on every segment of the *resolved* path, with case
ignored and trailing dots stripped, because on Windows `.Claude.\` and
`.claude\` are the same directory. That came out of an adversarial pass over
my own code, not out of theory.

## Detecting vs. gating

Shell commands still ask in a tainted session, even ones that look local, like
`npm test`. I tried ungating "local-looking" commands with the same
network-pattern list I use to *detect* taint, and dropped the idea, because the
list does a different job in each place.

Before the taint, nobody is trying to slip past the pattern list. The agent
writes `curl` because it wants `curl`, so a list of network commands is good
enough to notice that outside text came in.

After the taint, the attacker writes the command. `node -e "fetch(...)"` is on
no list. A pattern list works for *detecting*, when the actor is not yet
hostile. It does not work for *gating*, when the hostile party writes the
input. A hook cannot cut a shell off the network. An OS sandbox can.

## Why not just auto mode?

Auto mode's classifier judges each action by how it looks. A good injection
asks for something that looks ordinary, like `npm test` or a one-line config
change. fail-closed never looks at the action. It asks because of where the
context has been.

It does not replace the classifier. While I was building this, the classifier
blocked two actions that fail-closed had no rule for. The classifier is smart
and text can argue with it. This rule is dumb and text can't. Run both.

I checked it live in auto mode: after a `WebFetch` tainted the session, a
`Read` went through with no prompt, an in-project write went through and was
logged, a write to a `.claude/` path prompted, and a `Bash` call prompted. 4
of 4 as expected.

## Where it came from

Each rule comes from a failure in my own agent setup:

1. **A desktop agent sent an email nobody approved.** Its confirm gate was
   written correctly and failed closed, but it never ran:
   `permissionMode: "bypassPermissions"` returns before `canUseTool` is
   called. A guard is only as real as the test that proves it fires.
2. **Allowlisted tools skipped the taint check.** Mail-reading tools sat on
   `allowedTools`, which skip the permission callback, and that callback was
   where the session got marked. So reading mail never tainted anything. That
   is why the marker now sits on `PostToolUse` with matcher `*`, which every
   tool call passes through.
3. **`git` rode along at the end of a chain.** "The owner runs git" had been a
   rule for months. It broke four times in three days, the last time as
   `git status --short` pasted onto the end of a long typecheck command. That
   became the second hook, `command-block`, which matches a program wherever
   it starts a command in a chain.

## Testing a guard at its edge

In one audit of my own projects, five of the seven worst defects were guards
that existed and never fired at their boundary. So the suite tests the edges: the project root itself, a
sibling directory whose name starts with the root's name, `..`, a symlink that
lands outside, a junction for a file that does not exist yet, a session id of
`../../escape`, garbage on stdin.

To check the tests themselves, I break the policy on purpose with mutants: a
naive `startsWith` containment check, an unknown tool treated as trusted,
control paths matched case-sensitively, `*` crossing directories, and more.
All 25 mutants fail the suite.

The failure behaviour is uneven on purpose. If the taint gate cannot read its
config or its state, it **asks**, because it is a security boundary. If the
command block breaks, it **allows**, because it enforces a preference and must
not stop real work. Neither hook ever answers `allow`. The worst either one can
do is add a prompt.

## What it does not do

- **A shell is still a hole for becoming tainted.** `python -c "import
  urllib…"` gets past the network patterns. Once the session is tainted by
  anything, every shell call asks.
- **Unasked edits can wait for a clean session.** A tainted session can edit a
  test file, and a later, clean session runs `npm test` without asking. The
  taint record lists those files; `"strict": true` closes the gap at the cost
  of a prompt per edit.
- **`bypassPermissions` is not verified yet.** Given incident #1, I won't claim
  it until the probe in the repo has been run.

## Try it

```
/plugin marketplace add NattawatRyu/fail-closed
/plugin install fail-closed@fail-closed
```

Node 18+, no dependencies. The config lives at user level only
(`~/.claude/fail-closed.json`). A cloned repo is exactly the stranger this tool
distrusts, so a project-level file saying "trust everything" would let that
stranger switch the guard off.

The idea I'm keeping from this is to tie trust to what the context has seen,
and to spend the user's attention only on what cannot be undone.
