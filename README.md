# Detection Lab

Detection-as-code for a Wazuh home lab: Sigma rules, validated and tested by replaying logs, with coverage measured by the tests.

**Status:** work in progress. Phase 1 covers two rules, a validator, and a test suite using synthetic logs.

## Components

| File | What it does |
|------|--------------|
| `rules/*.yml` | One Sigma rule per detection, tagged with an ATT&CK technique. |
| `tools/sigma_lite.py` | Loads and validates rules and matches them against log lines. Supports only the Sigma keyword subset these rules use. |
| `tests/` | Checks that each rule is valid, fires on attack logs, and stays silent on benign logs. |

## Usage

    pip install -r requirements.txt
    pytest

## Limitations

- Fixtures are synthetic for now. Later phases replace them with logs captured from simulated attacks.
- The matcher is a small test harness, not a full Sigma engine.
