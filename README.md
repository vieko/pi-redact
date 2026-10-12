# pi-redact

A pi extension that keeps secrets out of session transcripts. A key that you paste, that a tool prints, or that sits in `AGENTS.md` becomes a stable placeholder such as `[REDACTED-SECRET-5c1e9a7b]`. The model works with the placeholder. When the model puts the placeholder in a local tool call, the extension puts the real value back first, so `curl -H "Authorization: Bearer [REDACTED-SECRET-5c1e9a7b]"` still authenticates.

A key that reaches the conversation stays there: pi sends it on every later turn, stores it in the session `.jsonl`, and replays it into forks, compaction and audits. The only fix is to keep it out.

Detection is vendored from [ray-amjad/claude-code-mods](https://github.com/ray-amjad/claude-code-mods/tree/main/plugins/transcript-redactor) (`src/detect.ts`, MIT): about 70 vendor key shapes, entropy tests, base64 that hides a key, passwords in URLs and CLI flags. See `NOTICE` for local changes.

## Where it hooks in

| pi event | What it does |
| :- | :- |
| `input` | Swaps keys in your prompt. `!cmd` runs as typed. |
| `before_agent_start` | Swaps keys in context files (secrets only). |
| `tool_call` | Puts real values back for local tools: `bash`, `powershell`, `write`, `edit`, `read`, `grep`, `find`, `ls`. Nested codemode calls are covered, because they go through the same event. |
| `tool_result` | Swaps keys in `content`, `structuredContent` and `details`. A value handed to a call is hidden again wherever its output prints it. A scan failure withholds the result. |
| `message_end` | Backstop for user, custom and tool-result messages before they persist. |
| `context` | Last net, per request: `!cmd` output, idle custom messages, and history from sessions recorded before the extension. |

Placeholders stay placeholders in `git commit`/`git tag` and `gh pr|issue|api|...`, and in every tool that is not in the restore list (`codemode` itself, `send_message`, MCP tools, web tools).

## Commands

`/redact` shows the count and settings. `/redact off` and `/redact on` toggle it for the session.

## Settings

Optional `~/.pi/agent/pi-redact.json`, same keys as the upstream plugin:

```json
{ "pii": false, "allow": "", "allowPrefixes": "", "restoreTools": "bash,write,edit,read,grep,find,ls", "notify": true }
```

`allowPrefixes` is added to the built-in public ids (`dpl_`, `prj_`, `team_`, `wrun_`, `gen_01`).

## Limits

- The vault lives in memory. After `/reload`, a restart or a resume, old placeholders no longer map to a value and reach tools as written.
- Output of `!cmd` is persisted by pi before any hook sees it. The model gets placeholders (the `context` net), but the raw output stays in the session file.
- Custom messages appended while pi is idle are persisted without `message_end`; the `context` net covers what the model sees.
- Sessions recorded before you install it keep their raw values on disk.

## Develop

```
npm install
npm run check            # tsc + extension tests + vendored detector tests
pi -ne -e ./extensions/pi-redact.ts
```
