"""Claude-powered triage, fix and rule generation."""
import json
import os
import tempfile
from pathlib import Path

import anthropic

from trustmebro import scanner
from trustmebro.scanner import Finding

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-5-5")
# Security prompts can trip the cyber classifier; "default" re-runs a declined request on a fallback model.
FALLBACK_BETA = "server-side-fallback-2026-07-01"

SYSTEM = (
    "You are TrustMeBro, a defensive application-security reviewer embedded in a developer's IDE. "
    "You review code that an AI coding agent is about to write into the developer's own repository, "
    "confirm or dismiss static-analysis findings, write safe patches, and write Semgrep rules that detect "
    "the vulnerable pattern. Never produce exploit payloads."
)

_client: anthropic.Anthropic | None = None


def client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        # Some hosts reserve ANTHROPIC_API_KEY for their own use; TRUSTMEBRO_ANTHROPIC_KEY is a fallback name.
        _client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY") or os.getenv("TRUSTMEBRO_ANTHROPIC_KEY"))
    return _client


def _ask_json(prompt: str, schema: dict, effort: str = "low") -> dict:
    response = client().beta.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM,
        betas=[FALLBACK_BETA],
        fallbacks="default",
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        messages=[{"role": "user", "content": prompt}],
    )
    if response.stop_reason == "refusal":
        raise RuntimeError(f"Claude declined: {getattr(response.stop_details, 'explanation', '')}")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def _finding_text(finding: Finding) -> str:
    return f"Rule: {finding.rule_id}\nFile: {finding.path}, line {finding.line}\nMessage: {finding.message}\nLine: {finding.code}"


TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "real": {"type": "boolean"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "explanation": {"type": "string"},
    },
    "required": ["real", "severity", "explanation"],
    "additionalProperties": False,
}


def triage(finding: Finding, context: str) -> dict:
    """Decide whether a finding is a real vulnerability. Returns {real, severity, explanation}."""
    prompt = (
        f"Semgrep flagged this code.\n\n{_finding_text(finding)}\n\nFull file:\n```\n{context}\n```\n\n"
        "Is this a real, reachable vulnerability (e.g. user input actually flows into it)? "
        "Explain the risk in one or two plain-English sentences a non-security developer understands."
    )
    return _ask_json(prompt, TRIAGE_SCHEMA)


FIX_SCHEMA = {
    "type": "object",
    "properties": {"fixed_code": {"type": "string"}, "summary": {"type": "string"}},
    "required": ["fixed_code", "summary"],
    "additionalProperties": False,
}


def propose_fix(finding: Finding, code: str) -> dict:
    """Return {fixed_code, summary}: the full file with the vulnerability removed and behavior kept."""
    prompt = (
        f"Fix this vulnerability.\n\n{_finding_text(finding)}\n\nFull file:\n```\n{code}\n```\n\n"
        "Return the complete corrected file. Change as little as possible and keep behavior the same."
    )
    return _ask_json(prompt, FIX_SCHEMA, effort="medium")


RULE_SCHEMA = {
    "type": "object",
    "properties": {"rule_id": {"type": "string"}, "yaml": {"type": "string"}},
    "required": ["rule_id", "yaml"],
    "additionalProperties": False,
}


def _rule_matches(rule_path: Path, code: str, suffix: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
        f.write(code)
    try:
        return bool(scanner.scan_paths([f.name], configs=[str(rule_path)]))
    finally:
        Path(f.name).unlink(missing_ok=True)


def write_rule(finding: Finding, vulnerable_code: str, fixed_code: str, attempts: int = 3) -> dict:
    """Generate a Semgrep rule that matches the vulnerable code but not the fix, and save it to rules/learned/.

    Returns {rule_id, path, yaml}. Retries with the failure reason until the rule validates and behaves.
    """
    suffix = Path(finding.path).suffix or ".py"
    feedback = ""
    for _ in range(attempts):
        prompt = (
            f"Write one Semgrep rule (YAML, top-level `rules:` list) for this confirmed bug.\n\n{_finding_text(finding)}\n\n"
            f"Vulnerable code:\n```\n{vulnerable_code}\n```\n\nFixed code:\n```\n{fixed_code}\n```\n\n"
            "The rule must match the vulnerable code and must NOT match the fixed code. Generalize it so it catches "
            "the same pattern elsewhere (other variable names, other functions, other string-building styles). "
            "Use an id starting with `trustmebro.learned.`." + feedback
        )
        rule = _ask_json(prompt, RULE_SCHEMA, effort="medium")
        path = scanner.LEARNED_RULES / f"{rule['rule_id'].split('.')[-1]}.yaml"
        path.write_text(rule["yaml"])

        if not scanner.validate_rule(str(path)):
            feedback = "\n\nYour previous rule was not valid Semgrep YAML:\n" + rule["yaml"]
        elif not _rule_matches(path, vulnerable_code, suffix):
            feedback = "\n\nYour previous rule did NOT match the vulnerable code:\n" + rule["yaml"]
        elif _rule_matches(path, fixed_code, suffix):
            feedback = "\n\nYour previous rule ALSO matched the fixed code (false positive):\n" + rule["yaml"]
        else:
            return {"rule_id": rule["rule_id"], "path": str(path), "yaml": rule["yaml"]}
        path.unlink(missing_ok=True)
    raise RuntimeError("could not produce a working rule" + feedback)


def hunt_variants(rule_path: str, root: str = ".") -> list[Finding]:
    """Run one learned rule across the repo to find sibling bugs."""
    return scanner.scan_paths([root], configs=[rule_path])
