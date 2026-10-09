# TrustMeBro

_TrustMeBro team project for the Cyber Defence Hackathon._

> Shift left was a start. TrustMeBro catches it the moment it's written.

TrustMeBro gives your codebase an immune system. It watches AI coding agents (Claude Code, Cursor, Pi) as they write code.
Every vulnerability it catches becomes an **trustmebro**: a Semgrep rule that hunts down every sibling of that bug in the repo.

## How it works

1. **Catch**: a PreToolUse hook sends every Write/Edit to TrustMeBro, which scans it with Semgrep.
2. **Triage**: Claude decides whether each finding is real and explains it in plain English.
3. **Fix**: TrustMeBro proposes a patch and verifies it in an Akash sandbox.
4. **Remember**: it writes a new Semgrep rule, validates it, and hunts variants across the repo.
5. **Prove**: every event lands in ClickHouse and shows up on the dashboard.

## Layout

| Path | What |
|---|---|
| `trustmebro/server.py` | FastMCP server exposing the tools |
| `trustmebro/scanner.py` | Semgrep runner |
| `trustmebro/brain.py` | Claude triage, fix and rule generation |
| `trustmebro/store.py` | ClickHouse logging |
| `trustmebro/hook.py` | Claude Code PreToolUse hook (blocks bad edits) |
| `db/schema.sql` | ClickHouse tables |
| `dashboard/app.py` | Streamlit dashboard |
| `.claude-plugin/`, `hooks/`, `commands/` | Claude Code plugin: MCP server, Write/Edit hook, `/trustmebro:hunt` |
| `integrations/` | Guild agent and Pi package |
| `deploy/` | Dockerfile and Akash SDL |

## Install in Claude Code

In Claude Code:

```
/plugin install trustmebro --marketplace divyachandana/trustmebro
```

Claude Code asks for your Anthropic API key (stored in your system keychain). That's it. On first start the plugin installs its own `uv`, Python dependencies and Semgrep into `~/.claude/plugins/data/`, which takes about 15 seconds once. Nothing goes on your global PATH.

You get the MCP tools (`scan_edit`, `triage`, `propose_fix`, `learn_rule`, `hunt_variants`), the hook that blocks vulnerable Write/Edit calls, and the `/trustmebro:hunt` command. Rules TrustMeBro learns are saved in your project under `.trustmebro/rules/`. Commit them and your whole team shares the memory.

ClickHouse logging is optional: set `CLICKHOUSE_HOST`, `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` to turn it on; without them it is skipped silently.

Try it on the vulnerable sample app: [TrustMeBroDemo](https://github.com/divyachandana/TrustMeBroDemo).

## Develop locally

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pipx install semgrep   # or: brew install semgrep. Keep it out of this venv: it pins an older `mcp` than fastmcp needs
cp .env.example .env   # fill in keys
trustmebro-mcp           # run the MCP server
```

Scan a file directly (set `TRUSTMEBRO_OFFLINE=1` to use only the local rules in `rules/base`, handy on hackathon wifi):

```bash
python -m trustmebro.scanner ../TrustMeBroDemo/app.py
```

Run the timed end-to-end demo (catch, triage, fix, learn, hunt) against the sample app:

```bash
python scripts/demo.py ../TrustMeBroDemo/app.py
```
