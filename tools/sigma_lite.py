"""Minimal Sigma keyword-rule loader, validator, and matcher for testing.

Supports only the Sigma subset these rules use: keyword lists
(case-insensitive, `*` wildcards) and conditions such as `a`,
`a and b`, `a or b`, `a and not b`, evaluated left to right.
It is a test harness, not a full Sigma engine. Wazuh conversion
uses pySigma.
"""
import re
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
REQUIRED = ("title", "id", "status", "description", "logsource",
            "detection", "level", "tags")
LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
UUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


def load_rules(rules_dir=RULES_DIR):
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        rule = yaml.safe_load(path.read_text())
        rule["_file"] = path.name
        rules.append(rule)
    return rules


def validate(rule):
    errors = [f"missing field: {k}" for k in REQUIRED if k not in rule]
    if errors:
        return errors
    if not UUID.match(str(rule["id"])):
        errors.append("id is not a lowercase UUID")
    if rule["level"] not in LEVELS:
        errors.append(f"bad level: {rule['level']}")
    if not any(ATTACK_TAG.match(t) for t in rule["tags"]):
        errors.append("no ATT&CK technique tag")
    det = rule["detection"]
    names = {k: v for k, v in det.items() if k != "condition"}
    if "condition" not in det:
        errors.append("detection has no condition")
        return errors
    if not all(isinstance(v, list) and v for v in names.values()):
        errors.append("each detection block must be a non-empty list")
    for tok in det["condition"].split():
        if tok not in ("and", "or", "not") and tok not in names:
            errors.append(f"condition uses undefined block: {tok}")
    return errors


def _hit(items, line):
    for item in items:
        pattern = ".*".join(re.escape(p) for p in item.split("*"))
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def matches(rule, line):
    det = rule["detection"]
    scope = {k: _hit(v, line) for k, v in det.items() if k != "condition"}
    result, op, negate = None, "and", False
    for tok in det["condition"].split():
        if tok in ("and", "or"):
            op = tok
        elif tok == "not":
            negate = True
        else:
            val = scope[tok] != negate
            negate = False
            if result is None:
                result = val
            elif op == "and":
                result = result and val
            else:
                result = result or val
    return bool(result)
