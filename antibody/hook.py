"""Claude Code PreToolUse hook: block Write/Edit calls that introduce vulnerabilities.

Reads the hook payload on stdin. Exit code 2 blocks the tool call and sends stderr back to Claude.
"""
import json
import sys
from pathlib import Path

from antibody import scanner


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
    # TODO(12:30): run brain.triage on each finding and only block confirmed ones
    if findings:
        lines = [f"- {f.rule_id} (line {f.line}): {f.message}" for f in findings]
        print("Antibody blocked this edit:\n" + "\n".join(lines), file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
