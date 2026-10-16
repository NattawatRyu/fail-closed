# ask-probe

Question: when a PreToolUse hook answers `"ask"` for a tool that is already on
`--allowedTools`, does each permission mode honour it?

Headless (`-p`) nobody can answer the prompt, so an honoured "ask" means the
tool does **not** run and `probe-<mode>.txt` is never created.

Run it yourself, by hand, one mode at a time (from this directory, Git Bash):

    HOOK="node $(pwd -W)/hook.mjs"
    S="{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"$HOOK\"}]}]}}"
    claude -p "Run exactly this bash command and nothing else: echo hi > probe-auto.txt" \
      --settings "$S" --permission-mode auto --allowedTools Bash --model haiku --max-turns 3
    ls probe-auto.txt; cat fired.log

Repeat with `default`, `acceptEdits`, `bypassPermissions`. Record results in the
table, then update the Limitations section of the top-level README.

| mode | hook fired | file created | ask honoured |
|---|---|---|---|
| default | | | |
| acceptEdits | | | |
| auto | | | |
| bypassPermissions | | | |
