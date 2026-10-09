"""Run the whole Antibody demo against demo_app/app.py and time each step.

1. Catch: the agent tries to write the /orders endpoint; Semgrep flags it and Claude confirms it.
2. Fix: Claude patches it.
3. Remember: Claude writes a Semgrep rule that matches the bug but not the fix.
4. Hunt: the new rule finds the sibling bugs in /products and /invoices.
"""
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from antibody import brain, scanner, store  # noqa: E402

DEMO = Path(__file__).resolve().parent.parent / "demo_app" / "app.py"


def step(name, fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    print(f"[{time.perf_counter() - start:5.1f}s] {name}")
    return result


def main() -> None:
    code = DEMO.read_text()
    findings = step("scan", scanner.scan_code, code, str(DEMO))
    first = min(findings, key=lambda f: f.line)
    print(f"        caught line {first.line}: {first.code}")

    verdict = step("triage", brain.triage, first, code)
    store.log_finding(first, "real" if verdict["real"] else "false_positive", blocked=verdict["real"], source="hook")
    print(f"        real={verdict['real']} [{verdict['severity']}] {verdict['explanation']}")

    fix = step("fix", brain.propose_fix, first, code)
    store.log_fix(first.rule_id, first.path, tests_passed=not any(
        f.line == first.line for f in scanner.scan_code(fix["fixed_code"], str(DEMO), include_learned=False)))
    print(f"        {fix['summary']}")

    # Learn from the one bug: the vulnerable endpoint vs. its fixed version.
    vulnerable = "\n".join(code.splitlines()[first.line - 4:first.line + 1])
    fixed_lines = fix["fixed_code"].splitlines()
    fixed = "\n".join(fixed_lines[first.line - 4:first.line + 1])
    rule = step("learn rule", brain.write_rule, first, vulnerable, fixed)
    print(f"        {rule['rule_id']} -> {rule['path']}")

    variants = step("hunt variants", brain.hunt_variants, rule["path"], str(DEMO.parent))
    for v in variants:
        store.log_finding(v, "pending", blocked=False, source="variant_hunt")
        print(f"        line {v.line}: {v.code}")
    store.log_rule(rule["rule_id"], rule["yaml"], variants_found=len(variants))


if __name__ == "__main__":
    main()
