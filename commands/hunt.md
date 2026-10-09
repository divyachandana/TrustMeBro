---
description: Scan this repo for vulnerabilities, fix them, and learn a rule from each one
---

Use the TrustMeBro MCP tools on this repository$ARGUMENTS:

1. Find the source files and call `scan_edit` on each with its current content.
2. Call `triage` on every finding. Skip the ones that are not real.
3. For the first real finding, call `propose_fix`, show me the diff, and apply it.
4. Call `learn_rule` with the vulnerable snippet and the fixed snippet. The rule is saved in `.trustmebro/rules/`.
5. Call `hunt_variants` with that rule's path and report every sibling bug it finds, with file and line.

Finish with one short summary: bugs blocked, fixed, rules learned, variants found.
