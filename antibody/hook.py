"""Claude Code PreToolUse hook: block Write/Edit calls that introduce vulnerabilities.

Reads the hook payload on stdin. Exit code 2 blocks the tool call and sends stderr back to Claude.
"""
import json
import sys
from pathlib import Path

from antibody import brain, scanner


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
    confirmed = []
    for f in findings:
        try:
            verdict = brain.triage(f, content)
        except Exception as e:  # no API key or API down: fail closed on Semgrep's word
            verdict = {"real": True, "severity": f.severity.lower(), "explanation": f"{f.message} (triage unavailable: {e})"}
        if verdict["real"]:
            confirmed.append((f, verdict))

    if confirmed:
        lines = [f"- line {f.line} [{v['severity']}]: {v['explanation']}" for f, v in confirmed]
        print(
            "Antibody blocked this edit because it introduces a vulnerability:\n" + "\n".join(lines)
            + "\nRewrite it safely (e.g. parameterized queries) and try again.",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
