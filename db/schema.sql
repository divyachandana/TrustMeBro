CREATE DATABASE IF NOT EXISTS antibody;

CREATE TABLE IF NOT EXISTS antibody.findings (
    ts        DateTime DEFAULT now(),
    rule_id   String,
    path      String,
    line      UInt32,
    severity  LowCardinality(String),
    verdict   LowCardinality(String),   -- real | false_positive | pending
    blocked   Bool,
    source    LowCardinality(String),   -- hook | mcp | variant_hunt
    message   String
) ENGINE = MergeTree ORDER BY (ts, rule_id);

CREATE TABLE IF NOT EXISTS antibody.rules (
    ts              DateTime DEFAULT now(),
    rule_id         String,
    yaml            String,
    variants_found  UInt32
) ENGINE = MergeTree ORDER BY (ts, rule_id);

CREATE TABLE IF NOT EXISTS antibody.fixes (
    ts            DateTime DEFAULT now(),
    rule_id       String,
    path          String,
    tests_passed  Bool
) ENGINE = MergeTree ORDER BY (ts, rule_id);
