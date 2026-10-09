"""Antibody MCP server: add it to Claude Code, Cursor or Pi."""
from dataclasses import asdict

from dotenv import load_dotenv
from fastmcp import FastMCP

from antibody import brain, scanner
from antibody.scanner import Finding

load_dotenv()
mcp = FastMCP("antibody")


@mcp.tool
def scan_edit(path: str, content: str) -> list[dict]:
    """Scan proposed file content before it is written. Returns Semgrep findings."""
    return [asdict(f) for f in scanner.scan_code(content, filename=path)]


@mcp.tool
def triage(finding: dict, context: str) -> dict:
    """Decide whether a finding is a real, reachable vulnerability."""
    return brain.triage(Finding(**finding), context)


@mcp.tool
def propose_fix(finding: dict, content: str) -> dict:
    """Return {fixed_code, summary}: a patched version of the content."""
    return brain.propose_fix(Finding(**finding), content)


@mcp.tool
def learn_rule(finding: dict, vulnerable_code: str, fixed_code: str) -> dict:
    """Turn a confirmed bug into a validated Semgrep rule saved under rules/learned/."""
    return brain.write_rule(Finding(**finding), vulnerable_code, fixed_code)


@mcp.tool
def hunt_variants(rule_path: str, root: str = ".") -> list[dict]:
    """Run a learned rule (path from learn_rule) across the repo to find sibling bugs."""
    return [asdict(f) for f in brain.hunt_variants(rule_path, root)]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
