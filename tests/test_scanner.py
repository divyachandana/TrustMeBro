from pathlib import Path

from antibody import scanner

DEMO = Path(__file__).resolve().parent.parent / "demo_app" / "app.py"


def test_demo_app_has_planted_sqli():
    findings = scanner.scan_paths([str(DEMO)], include_learned=False)
    assert findings, "expected Semgrep to flag the planted SQL injections"
