"""Log findings, fixes and learned rules to ClickHouse."""
import os
from functools import lru_cache

import clickhouse_connect


@lru_cache
def db():
    return clickhouse_connect.get_client(
        host=os.environ["CLICKHOUSE_HOST"],
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "antibody"),
        secure=True,
    )


def log_finding(finding, verdict: str, blocked: bool, source: str) -> None:
    # TODO(2:15)
    pass


def log_rule(rule_id: str, yaml_text: str, variants_found: int) -> None:
    # TODO(2:15)
    pass


def log_fix(rule_id: str, path: str, tests_passed: bool) -> None:
    # TODO(2:15)
    pass
