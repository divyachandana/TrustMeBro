# Antibody

_TrustMeBro team project for the Cyber Defence Hackathon._

> Shift left was a start. Antibody catches it the moment it's written.

Antibody gives your codebase an immune system. It watches AI coding agents (Claude Code, Cursor, Pi) as they write code.
Every vulnerability it catches becomes an **antibody**: a Semgrep rule that hunts down every sibling of that bug in the repo.

## How it works

1. **Catch**: a PreToolUse hook sends every Write/Edit to Antibody, which scans it with Semgrep.
2. **Triage**: Claude decides whether each finding is real and explains it in plain English.
3. **Fix**: Antibody proposes a patch and verifies it in an Akash sandbox.
4. **Remember**: it writes a new Semgrep rule, validates it, and hunts variants across the repo.
5. **Prove**: every event lands in ClickHouse and shows up on the dashboard.

## Layout

| Path | What |
|---|---|
| `antibody/server.py` | FastMCP server exposing the tools |
| `antibody/scanner.py` | Semgrep runner |
| `antibody/brain.py` | Claude triage, fix and rule generation |
| `antibody/store.py` | ClickHouse logging |
| `antibody/hook.py` | Claude Code PreToolUse hook (blocks bad edits) |
| `db/schema.sql` | ClickHouse tables |
| `dashboard/app.py` | Streamlit dashboard |
| `demo_app/` | Flask app with 3 planted SQL injections |
| `integrations/` | Guild agent and Pi package |
| `deploy/` | Dockerfile and Akash SDL |

## Quickstart

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pipx install semgrep   # or: brew install semgrep. Keep it out of this venv: it pins an older `mcp` than fastmcp needs
cp .env.example .env   # fill in keys
antibody-mcp           # run the MCP server
```

Scan a file directly (set `ANTIBODY_OFFLINE=1` to use only the local rules in `rules/base`, handy on hackathon wifi):

```bash
python -m antibody.scanner demo_app/app.py
```
