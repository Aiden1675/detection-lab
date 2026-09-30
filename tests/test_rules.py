from pathlib import Path

import pytest
import yaml

from tools.sigma_lite import load_rules, matches, validate

HERE = Path(__file__).parent
CAPTURED = HERE / "captured"
FIXTURES = yaml.safe_load((HERE / "fixtures.yml").read_text())
RULES = load_rules()
IDS = [r["_file"] for r in RULES]


def read_scenario(name):
    path = CAPTURED / f"{name}.log"
    assert path.exists(), f"missing capture: {path.name}"
    lines = path.read_text().splitlines()
    assert lines, f"empty capture: {path.name}"
    return lines


def attack_names(rule):
    entry = FIXTURES["rules"].get(rule["id"])
    assert entry, f"no fixtures for {rule['_file']}"
    return entry["attack"]


def test_rule_ids_are_unique():
    ids = [r["id"] for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_rule_is_valid(rule):
    assert validate(rule) == []


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_fires_on_attack_logs(rule):
    for name in attack_names(rule):
        lines = read_scenario(name)
        assert any(matches(rule, line) for line in lines), (
            f"{rule['_file']} did not fire on scenario {name}"
        )


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_silent_on_benign_logs(rule):
    for name in FIXTURES["benign"]:
        for line in read_scenario(name):
            assert not matches(rule, line), f"false positive in {name}: {line}"
