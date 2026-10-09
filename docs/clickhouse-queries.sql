-- Paste into the ClickHouse Cloud SQL console. Tables are created automatically on first log.

-- 1. Latest catches: what was blocked, where, and by which rule
SELECT ts, path, line, severity, verdict, blocked, source, rule_id
FROM trustmebro.findings
ORDER BY ts DESC
LIMIT 20;

-- 2. Learned vs built-in rules: who is catching what
SELECT
    multiIf(rule_id LIKE '%trustmebro.learned.%', 'learned',
            rule_id LIKE '%rules.base.%' OR rule_id LIKE 'trustmebro.%', 'base',
            'semgrep registry') AS rule_source,
    count() AS findings,
    countIf(blocked) AS edits_blocked
FROM trustmebro.findings
GROUP BY rule_source
ORDER BY findings DESC;

-- 3. Rules TrustMeBro learned, and how many sibling bugs each one found
SELECT ts, rule_id, variants_found
FROM trustmebro.rules
ORDER BY ts DESC;

-- 4. Fixes applied, and whether the patched code scanned clean
SELECT ts, path, rule_id, tests_passed
FROM trustmebro.fixes
ORDER BY ts DESC;
