from pathlib import Path

import pytest
import yaml

from tools.sigma_lite import load_rules, matches, validate

FIXTURES = yaml.safe_load((Path(__file__).parent / "fixtures.yml").read_text())
RULES = load_rules()
IDS = [r["_file"] for r in RULES]


def fixture_lines(rule, kind):
    assert rule["id"] in FIXTURES, f"no fixtures for {rule['_file']}"
    lines = FIXTURES[rule["id"]][kind]
    assert lines, f"no {kind} lines for {rule['_file']}"
    return lines


def test_rule_ids_are_unique():
    ids = [r["id"] for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_rule_is_valid(rule):
    assert validate(rule) == []


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_fires_on_attack_logs(rule):
    for line in fixture_lines(rule, "attack"):
        assert matches(rule, line), f"missed attack line: {line}"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_silent_on_benign_logs(rule):
    for line in fixture_lines(rule, "benign"):
        assert not matches(rule, line), f"false positive: {line}"
