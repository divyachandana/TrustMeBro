"""Log findings, fixes and learned rules to ClickHouse.

Logging is best-effort: with no CLICKHOUSE_HOST set, or ClickHouse down, every call is a no-op
so the hook and MCP tools never fail because of the dashboard.
"""
import os
import sys
from functools import lru_cache
from pathlib import Path

SCHEMA = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


@lru_cache
def db():
    if not os.getenv("CLICKHOUSE_HOST"):
        return None
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=os.environ["CLICKHOUSE_HOST"],
        port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        secure=os.getenv("CLICKHOUSE_SECURE", "1") != "0",
        connect_timeout=5,
    )
    for statement in SCHEMA.read_text().split(";"):
        if statement.strip():
            client.command(statement)
    return client


def _insert(table: str, columns: list[str], row: list) -> None:
    try:
        client = db()
        if client is not None:
            client.insert(f"trustmebro.{table}", [row], column_names=columns)
    except Exception as e:  # never break a scan over logging
        print(f"trustmebro: ClickHouse logging skipped ({e})", file=sys.stderr)


def log_finding(finding, verdict: str, blocked: bool, source: str) -> None:
    _insert(
        "findings",
        ["rule_id", "path", "line", "severity", "verdict", "blocked", "source", "message"],
        [finding.rule_id, finding.path, finding.line, finding.severity.lower(), verdict, blocked, source, finding.message],
    )


def log_rule(rule_id: str, yaml_text: str, variants_found: int) -> None:
    _insert("rules", ["rule_id", "yaml", "variants_found"], [rule_id, yaml_text, variants_found])


def log_fix(rule_id: str, path: str, tests_passed: bool) -> None:
    _insert("fixes", ["rule_id", "path", "tests_passed"], [rule_id, path, tests_passed])
