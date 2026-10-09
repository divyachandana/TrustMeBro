---
description: Show what TrustMeBro has caught, fixed and learned in this repo
---

Read `.trustmebro/log.jsonl` (one JSON event per line; `kind` is findings, fixes or rules). Show:

1. The last 10 findings: time, file:line, rule, whether the edit was blocked. Label each rule as learned (id contains `trustmebro.learned.`), base, or Semgrep registry.
2. Totals: edits blocked, fixes applied, rules learned, sibling bugs found by learned rules.

Keep it to one short table plus one line of totals. If the file doesn't exist yet, say nothing has been logged.
