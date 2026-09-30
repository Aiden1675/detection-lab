import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

from tools.sigma_lite import load_rules
from tools.sigma_to_wazuh import MAP, OUT, render

HERE = Path(__file__).parent
FIXTURES = yaml.safe_load((HERE / "fixtures.yml").read_text())
META = yaml.safe_load(MAP.read_text())
RULES = load_rules()
HEADER = re.compile(
    r"^\S+\s+\S+\s+(?P<prog>[\w.\-]+)(?:\[\d+\])?:\s(?P<body>.*)$"
)


def test_generated_file_is_current():
    assert OUT.read_text() == render(), "run: python3 -m tools.sigma_to_wazuh"


def test_generated_xml_is_well_formed():
    ET.fromstring(OUT.read_text())


def converted_patterns():
    root = ET.fromstring(OUT.read_text())
    return {r.get("id"): r.find("regex").text for r in root.iter("rule")}


def bodies(name, program):
    """Log bodies the way Wazuh sees them: header and program name removed."""
    out = []
    for line in (HERE / "captured" / f"{name}.log").read_text().splitlines():
        m = HEADER.match(line)
        if m and m.group("prog") == program:
            out.append(m.group("body"))
    return out


def fires(pattern, names, program):
    return any(re.search(pattern, b) for n in names for b in bodies(n, program))


@pytest.mark.parametrize("rule", RULES, ids=[r["_file"] for r in RULES])
def test_converted_regex_behaves_like_the_sigma_rule(rule):
    meta = META[rule["id"]]
    pattern = converted_patterns()[str(meta["wazuh_id"])]
    for name in FIXTURES["rules"][rule["id"]]["attack"]:
        assert fires(pattern, [name], meta["program"]), f"missed {name}"
    assert not fires(pattern, FIXTURES["benign"], meta["program"])
