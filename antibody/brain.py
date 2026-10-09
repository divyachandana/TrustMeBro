"""Claude-powered triage, fix and rule generation."""
import os

from anthropic import Anthropic

from antibody.scanner import Finding

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
_client: Anthropic | None = None


def client() -> Anthropic:
    global _client
    if _client is None:
        _client = Anthropic()
    return _client


def triage(finding: Finding, context: str) -> dict:
    """Decide whether a finding is a real vulnerability. Returns {real, explanation}."""
    # TODO(12:30): prompt Claude with the finding + surrounding code, parse JSON verdict
    raise NotImplementedError


def propose_fix(finding: Finding, code: str) -> str:
    """Return a patched version of `code` that removes the vulnerability."""
    # TODO(12:30)
    raise NotImplementedError


def write_rule(finding: Finding, vulnerable_code: str, fixed_code: str) -> str:
    """Return a Semgrep YAML rule that matches the vulnerable pattern but not the fix."""
    # TODO(1:30): generate rule, then check with scanner.validate_rule and re-scan both snippets
    raise NotImplementedError
