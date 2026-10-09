"""TrustMeBro MCP server: add it to Claude Code, Cursor or Pi."""
from dataclasses import asdict
from pathlib import Path

from dotenv import load_dotenv
from fastmcp import FastMCP

from trustmebro import brain, scanner, store
from trustmebro.scanner import Finding

load_dotenv()
mcp = FastMCP("trustmebro")


@mcp.tool
def scan_edit(path: str, content: str) -> list[dict]:
    """Scan proposed file content before it is written. Returns Semgrep findings."""
    return [asdict(f) for f in scanner.scan_code(content, filename=path)]


@mcp.tool
def triage(finding: dict, context: str) -> dict:
    """Decide whether a finding is a real, reachable vulnerability."""
    f = Finding(**finding)
    verdict = brain.triage(f, context)
    store.log_finding(f, "real" if verdict["real"] else "false_positive", blocked=False, source="mcp")
    return verdict


@mcp.tool
def propose_fix(finding: dict, content: str) -> dict:
    """Return {fixed_code, summary}: a patched version of the content."""
    f = Finding(**finding)
    fix = brain.propose_fix(f, content)
    still_vulnerable = bool(scanner.scan_code(fix["fixed_code"], filename=f.path, include_learned=False))
    store.log_fix(f.rule_id, f.path, tests_passed=not still_vulnerable)
    return fix


@mcp.tool
def learn_rule(finding: dict, vulnerable_code: str, fixed_code: str) -> dict:
    """Turn a confirmed bug into a validated Semgrep rule saved in the project's .trustmebro/rules/."""
    rule = brain.write_rule(Finding(**finding), vulnerable_code, fixed_code)
    store.log_rule(rule["rule_id"], rule["yaml"], variants_found=0)
    return rule


@mcp.tool
def hunt_variants(rule_path: str, root: str = ".") -> list[dict]:
    """Run a learned rule (path from learn_rule) across the repo to find sibling bugs."""
    variants = brain.hunt_variants(rule_path, root)
    for f in variants:
        store.log_finding(f, "pending", blocked=False, source="variant_hunt")
    store.log_rule(Path(rule_path).stem, Path(rule_path).read_text(), variants_found=len(variants))
    return [asdict(f) for f in variants]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
