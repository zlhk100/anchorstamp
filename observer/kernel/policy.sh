#!/bin/bash
# observer/kernel/policy.sh — add the IMA rule the anchorstamp_exec module
# measures under. Root, once per boot, before load.sh.
#
#   sudo observer/kernel/policy.sh
#
# On a kernel built without CONFIG_IMA_WRITE_POLICY a valid write removes
# the policy file until the next boot, so the rule cannot be changed or
# added to later in that boot. If the file is already absent, a policy was
# written this boot: refuse and say so.
set -euo pipefail

POLICY=/sys/kernel/security/ima/policy
RULE='measure func=CRITICAL_DATA label=anchorstamp pcr=13 template=ima-buf'

[ "$(id -u)" = 0 ] || { echo "policy.sh: run as root" >&2; exit 1; }
echo "policy.sh $(date -Is) kernel $(uname -r)"
if [ ! -e "$POLICY" ]; then
    echo "REFUSED: $POLICY is absent: a policy was already written this boot"
    exit 1
fi
ls -l "$POLICY"
# Record any built-in policy chosen on the kernel command line, so the log
# shows what was in force when the rule was written.
builtin=$(tr ' ' '\n' </proc/cmdline | grep '^ima_policy=' || true)
echo "kernel command line ima_policy: ${builtin:-none}"
echo "writing: $RULE"
if ! printf '%s\n' "$RULE" >"$POLICY"; then
    echo "FAILED: the kernel rejected the rule"
    dmesg | grep -i ima | tail -n 5 || true
    exit 1
fi
if [ -e "$POLICY" ]; then
    echo "written; $POLICY still present"
else
    echo "written; $POLICY now absent until reboot"
fi
