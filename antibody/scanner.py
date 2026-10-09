"""Run Semgrep on files or raw code and return normalized findings."""
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
BASE_RULES = RULES_DIR / "base"  # local rules, work offline
LEARNED_RULES = RULES_DIR / "learned"
# Registry packs need network access to semgrep.dev; set ANTIBODY_OFFLINE=1 to skip them.
REGISTRY_CONFIGS = [] if os.getenv("ANTIBODY_OFFLINE") else ["p/python", "p/owasp-top-ten"]


@dataclass
class Finding:
    rule_id: str
    path: str
    line: int
    severity: str
    message: str
    code: str


def _configs(include_learned: bool) -> list[str]:
    configs = [str(BASE_RULES), *REGISTRY_CONFIGS]
    if include_learned and any(LEARNED_RULES.glob("*.yaml")):
        configs.append(str(LEARNED_RULES))
    return configs


def scan_paths(paths: list[str], configs: list[str] | None = None, include_learned: bool = True) -> list[Finding]:
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
    for c in configs or _configs(include_learned):
        cmd += ["--config", c]
    proc = subprocess.run(cmd + paths, capture_output=True, text=True)
    output = json.loads(proc.stdout) if proc.stdout.strip() else {}
    if proc.returncode not in (0, 1) or not output:
        errors = [e.get("message", "") for e in output.get("errors", [])]
        raise RuntimeError(f"semgrep failed: {proc.stderr.strip() or errors}")
    results = output.get("results", [])
    # Semgrep OSS returns "requires login" for extra.lines, so read the line ourselves.
    def source_line(r):
        try:
            return Path(r["path"]).read_text().splitlines()[r["start"]["line"] - 1].strip()
        except (OSError, IndexError):
            return ""

    return [
        Finding(
            rule_id=r["check_id"],
            path=r["path"],
            line=r["start"]["line"],
            severity=r["extra"].get("severity", "INFO"),
            message=r["extra"].get("message", ""),
            code=source_line(r),
        )
        for r in results
    ]


def scan_code(code: str, filename: str = "snippet.py", **kwargs) -> list[Finding]:
    """Scan code that hasn't been written to disk yet (e.g. a proposed edit)."""
    suffix = Path(filename).suffix or ".py"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
        f.write(code)
    try:
        findings = scan_paths([f.name], **kwargs)
    finally:
        Path(f.name).unlink(missing_ok=True)
    for finding in findings:
        finding.path = filename
    return findings


def validate_rule(rule_path: str) -> bool:
    proc = subprocess.run(["semgrep", "--validate", "--config", rule_path], capture_output=True, text=True)
    return proc.returncode == 0


if __name__ == "__main__":
    for finding in scan_paths(sys.argv[1:]):
        print(json.dumps(asdict(finding)))
