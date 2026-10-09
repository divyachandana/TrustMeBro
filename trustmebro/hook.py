"""Claude Code PreToolUse hook: block Write/Edit calls that introduce vulnerabilities.

Reads the hook payload on stdin. Exit code 2 blocks the tool call and sends stderr back to Claude.
"""
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from trustmebro import brain, scanner, store


def proposed_content(tool_name: str, tool_input: dict) -> str | None:
    if tool_name == "Write":
        return tool_input.get("content")
    if tool_name == "Edit":
        path = Path(tool_input["file_path"])
        original = path.read_text() if path.exists() else ""
        return original.replace(tool_input["old_string"], tool_input["new_string"], 1)
    return None


def main() -> None:
    payload = json.load(sys.stdin)
    tool_input = payload.get("tool_input", {})
    content = proposed_content(payload.get("tool_name", ""), tool_input)
    if not content:
        sys.exit(0)

    findings = scanner.scan_code(content, filename=tool_input.get("file_path", "snippet.py"))

    def check(f):
        try:
            return f, brain.triage(f, content)
        except Exception as e:  # no API key or API down: fail closed on Semgrep's word
            return f, {"real": True, "severity": f.severity.lower(), "explanation": f"{f.message} (triage unavailable: {e})"}

    with ThreadPoolExecutor(max_workers=8) as pool:
        verdicts = list(pool.map(check, findings))
    confirmed = [(f, v) for f, v in verdicts if v["real"]]
    for f, v in verdicts:
        store.log_finding(f, "real" if v["real"] else "false_positive", blocked=v["real"], source="hook")

    if confirmed:
        lines = [f"- line {f.line} [{v['severity']}]: {v['explanation']}" for f, v in confirmed]
        print(
            "TrustMeBro blocked this edit because it introduces a vulnerability:\n" + "\n".join(lines)
            + "\nRewrite it safely (e.g. parameterized queries) and try again.",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
