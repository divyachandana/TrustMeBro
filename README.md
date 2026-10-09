# TrustMeBro

> Shift left was a start. TrustMeBro catches it the moment it's written.

A Claude Code plugin that blocks vulnerable code as your AI agent writes it, fixes it, and turns each bug into a Semgrep rule that finds its siblings.

## Install

In Claude Code:

```
/plugin install trustmebro --marketplace divyachandana/trustmebro
```

Paste your Anthropic API key when asked. That's it. The first session takes about 15 seconds while the plugin sets up Semgrep and its dependencies.

To change the key later:

```
/plugin configure trustmebro@trustmebro
```

## Use

| You do | TrustMeBro does |
|---|---|
| Let Claude write code as usual | Blocks any Write/Edit that adds a vulnerability and tells Claude how to fix it |
| Run `/trustmebro:hunt` | Scans the repo, fixes a bug, learns a rule from it, and finds similar bugs |

Learned rules are saved in `.trustmebro/rules/`. Commit them so your whole team gets them.

## Try it

```
git clone https://github.com/divyachandana/TrustMeBroDemo
cd TrustMeBroDemo
claude
```

Then follow [DEMO.md](https://github.com/divyachandana/TrustMeBroDemo/blob/main/DEMO.md).

## Update

```
/plugin marketplace update trustmebro
```

Then restart Claude Code.

## Optional: ClickHouse logging

Every catch, fix and learned rule can be logged to ClickHouse Cloud. Add your service's connection details (from its **Connect** panel, not the console API key) to a `.env` in your project:

```
CLICKHOUSE_HOST=xxxx.us-east-1.aws.clickhouse.cloud
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=...
```

Tables are created on first use. Open the service's **SQL console** and paste queries from [docs/clickhouse-queries.sql](docs/clickhouse-queries.sql). Without these settings, logging is skipped.

## Develop

```bash
brew install uv semgrep
uv sync --extra dev
uv run pytest
uv run python scripts/demo.py ../TrustMeBroDemo/app.py
```
