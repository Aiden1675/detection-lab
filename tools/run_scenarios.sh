#!/usr/bin/env bash
# Runs attack and benign scenarios on this lab VM and saves the auth.log
# lines each one produces to tests/captured/. Only run it on a VM you own.
# Lines from this script's own sudo wc/tail calls are filtered out.
set -u
cd "$(dirname "$0")/.."
mkdir -p tests/captured
LOG=/var/log/auth.log
R=""
[ -r "$LOG" ] || R="sudo"
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

sudo -v
sudo userdel -r svc_backup 2>/dev/null
sudo userdel -r svc_del 2>/dev/null
sudo userdel svc_probe 2>/dev/null
sudo useradd -m svc_del 2>/dev/null

capture() {
  name=$1; shift
  start=$($R wc -l "$LOG" | cut -d' ' -f1)
  bash -c "$1" >/dev/null 2>&1
  sleep 2
  $R tail -n +$((start + 1)) "$LOG" \
    | grep -v -e 'COMMAND=/usr/bin/tail' -e 'COMMAND=/usr/bin/wc' \
    > "tests/captured/$name.log"
  echo "$name: $(wc -l < "tests/captured/$name.log") lines"
}

# Attacks
capture attack_useradd 'sudo useradd -m -s /bin/bash svc_backup'
capture attack_usermod_sudo 'sudo usermod -aG sudo svc_backup'
capture attack_root_shell 'echo exit | sudo bash'
capture attack_su_dash 'echo exit | sudo su -'
capture attack_ssh_invalid_user "$SSH nosuchuser@127.0.0.1 true"
capture attack_sudo_failed 'echo wrongpass | sudo -S -k true'
capture attack_userdel 'sudo userdel -r svc_del'

# Benign activity the rules must stay quiet on
capture benign_usermod_video 'sudo usermod -aG video svc_backup'
capture benign_useradd_system 'sudo useradd -r -s /usr/sbin/nologin svc_probe'
capture benign_ssh_valid_user "$SSH vboxuser@127.0.0.1 true"
capture benign_apt_simulate 'sudo apt-get -s upgrade'
capture benign_systemctl 'sudo systemctl status ssh --no-pager'
capture benign_ls_root 'sudo ls /root'

sudo userdel -r svc_backup 2>/dev/null
sudo userdel -r svc_del 2>/dev/null
sudo userdel svc_probe 2>/dev/null
echo "Done. Review tests/captured/ before committing."
