# Detection Lab

![tests](https://github.com/Aiden1675/detection-lab/actions/workflows/ci.yml/badge.svg)

Detection-as-code for a Wazuh home lab: Sigma rules tested by replaying real attack logs, converted to Wazuh rules, and verified firing in a live Wazuh instance.

**Status:** work in progress. Two detections so far.

## Components

| File | What it does |
|------|--------------|
| `rules/*.yml` | One Sigma rule per detection, tagged with an ATT&CK technique. Currently new local user (T1136.001), root shell via sudo (T1548.003), and user added to the sudo group (T1098). |
| `tools/sigma_lite.py` | Loads and validates rules and matches them against log lines. Supports only the Sigma keyword subset these rules use. |
| `tools/sigma_to_wazuh.py` | Converts each Sigma rule into a Wazuh rule with a PCRE2 regex and ATT&CK tags, using `tools/wazuh_map.yml` for rule ids and parent rules. |
| `tools/run_scenarios.sh` | Runs attack and benign commands on the lab VM and saves the `auth.log` lines each one produces to `tests/captured/`. |
| `wazuh/detection_lab_rules.xml` | The generated Wazuh rules file. Do not edit by hand. |
| `tests/` | Checks that rules are valid, fire on captured attack logs, stay silent on captured benign logs, and that the generated Wazuh file is current and behaves like the Sigma rule. |
| `tools/coverage_report.py` | Re-checks every rule against the captured logs and writes `docs/coverage.md` and an ATT&CK Navigator layer. A technique counts as covered only if its rule passes the replay tests. |

## Requirements

Python 3 with `pyyaml` and `pytest`. Wazuh is only needed to deploy the rules and run the live check. `run_scenarios.sh` needs sudo on an Ubuntu VM that writes `/var/log/auth.log`.

## Usage

```bash
pip install -r requirements.txt
pytest
python3 -m tools.sigma_to_wazuh
bash tools/run_scenarios.sh   # lab VM only
```

To deploy, copy `wazuh/detection_lab_rules.xml` to `/var/ossec/etc/rules/`, run `wazuh-analysisd -t`, then restart `wazuh-manager`.

## Results

Run on a single Ubuntu lab VM with Wazuh 4.14:

- **Tests:** 15 pass. Both rules fire on their captured attack logs and stay silent on five captured benign scenarios, including a system-account `useradd` with a `nologin` shell.
- **Wazuh engine:** replaying every capture through `wazuh-logtest` fires rule 100100 on the `useradd` attack and rule 100101 on both sudo attacks. No benign capture triggers any rule.
- **Live run:** creating a user, opening a root shell, and adding a user to the sudo group on the VM each produced an alert. The 100100 alert carried `T1136.001` and the Persistence tactic.
- **Finding:** Wazuh reports the first time a user runs a sudo command as rule 5403 and repeats as 5402, both children of 5400. A custom rule parented on only one of them can miss events, so the sudo rule lists both.
- **Sudo-group detection:** Wazuh has no built-in rule for `usermod` group changes, so this rule matches on the program name. It fires on adding a user to `sudo` and stays silent on adding one to `video`, in both `wazuh-logtest` and a live run.
- 

## Limitations and next steps

- Only three detections, each tested against captures from one VM and one user. They say little about other environments.
- `sigma_lite.py` and the converter handle a small Sigma subset (keyword lists joined by `and` / `and not`), not full Sigma. Replacing them with pySigma is a next step.
- The sudo rule matches any `sudo bash`, including legitimate admin shells (`sudo -i`). Expect false positives in real use.
- The attack captures come from commands run by the scenario script, not from real adversary tooling.
- The sudo-group rule only covers `usermod`. Other ways to gain sudo rights, such as `gpasswd` or editing `/etc/group`, are not tested.
- CI runs the log-replay tests only. The live Wazuh check is done by hand on the lab VM.
- Not yet built: more detections.

## Safety

`run_scenarios.sh` changes the system: it creates and deletes two test users and opens root shells. Run it only on a VM you own. The converter and tests only read files and write `wazuh/detection_lab_rules.xml`.
