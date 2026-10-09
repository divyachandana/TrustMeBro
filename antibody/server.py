"""Antibody MCP server: add it to Claude Code, Cursor or Pi."""
from dataclasses import asdict

from dotenv import load_dotenv
from fastmcp import FastMCP

from antibody import scanner

load_dotenv()
mcp = FastMCP("antibody")


@mcp.tool
def scan_edit(path: str, content: str) -> list[dict]:
    """Scan proposed file content before it is written. Returns Semgrep findings."""
    return [asdict(f) for f in scanner.scan_code(content, filename=path)]


@mcp.tool
def triage(finding: dict, context: str) -> dict:
    """Decide whether a finding is a real, reachable vulnerability."""
    raise NotImplementedError  # TODO(12:30): brain.triage


@mcp.tool
def propose_fix(finding: dict, content: str) -> str:
    """Return a patched version of the content."""
    raise NotImplementedError  # TODO(12:30): brain.propose_fix


@mcp.tool
def learn_rule(finding: dict, vulnerable_code: str, fixed_code: str) -> str:
    """Turn a confirmed bug into a validated Semgrep rule saved under rules/learned/."""
    raise NotImplementedError  # TODO(1:30): brain.write_rule + scanner.validate_rule


@mcp.tool
def hunt_variants(rule_id: str, root: str = ".") -> list[dict]:
    """Run a learned rule across the repo to find sibling bugs."""
    raise NotImplementedError  # TODO(1:30)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
