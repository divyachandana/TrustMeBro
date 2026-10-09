"""Run Semgrep on files or raw code and return normalized findings."""
import functools
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

BASE_RULES = Path(__file__).resolve().parent.parent / "rules" / "base"  # ships with the plugin, works offline
# Learned rules are the project's memory, so they live in the project being protected, not in the plugin.
LEARNED_RULES = Path(
    os.getenv("TRUSTMEBRO_RULES_DIR")
    or Path(os.getenv("CLAUDE_PROJECT_DIR") or Path.cwd()) / ".trustmebro" / "rules"
)
# Registry packs need network access to semgrep.dev; set TRUSTMEBRO_OFFLINE=1 to skip them.
REGISTRY_PACKS = ["p/python", "p/owasp-top-ten"]
# Semgrep's version check blocks for ~90s when semgrep.dev is slow or unreachable.
SEMGREP_ENV = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


@dataclass
class Finding:
    rule_id: str
    path: str
    line: int
    severity: str
    message: str
    code: str


@functools.cache
def _registry_reachable() -> bool:
    """Semgrep stalls ~100s and then fails when semgrep.dev is blocked, so probe it once first."""
    if os.getenv("TRUSTMEBRO_OFFLINE"):
        return False
    try:
        urllib.request.urlopen("https://semgrep.dev/c/p/python", timeout=3).close()
        return True
    except (OSError, urllib.error.URLError):
        print("trustmebro: semgrep.dev unreachable, using local rules only", file=sys.stderr)
        return False


def _configs(include_learned: bool) -> list[str]:
    configs = [str(BASE_RULES), *(REGISTRY_PACKS if _registry_reachable() else [])]
    if include_learned and any(LEARNED_RULES.glob("*.yaml")):
        configs.append(str(LEARNED_RULES))
    return configs


def scan_paths(paths: list[str], configs: list[str] | None = None, include_learned: bool = True) -> list[Finding]:
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
    for c in configs or _configs(include_learned):
        cmd += ["--config", c]
    proc = subprocess.run(cmd + paths, capture_output=True, text=True, env=SEMGREP_ENV)
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
    # `semgrep --validate` downloads lint rules from semgrep.dev; a local scan of an empty file is offline and ~2s.
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("\n")
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
             "--config", rule_path, f.name],
            capture_output=True, text=True, env=SEMGREP_ENV,
        )
    finally:
        Path(f.name).unlink(missing_ok=True)
    try:
        return proc.returncode in (0, 1) and not json.loads(proc.stdout).get("errors")
    except json.JSONDecodeError:
        return False


if __name__ == "__main__":
    for finding in scan_paths(sys.argv[1:]):
        print(json.dumps(asdict(finding)))
