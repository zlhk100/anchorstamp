#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright © 2026 Lei Zhou
# scripts/dev-venv.sh <dir> — build the operator's development venv (ruff,
# for scripts/check.sh CS-PY-1) from demo/framework/requirements-dev.lock.
# Hash-checked install, binary wheels only. Refuses if <dir> exists.
# Runs as the operator, never as root.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <dir>" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "$0: not as root" >&2; exit 2; }
dir=$1
lock="$(dirname "$0")/../demo/framework/requirements-dev.lock"
[ ! -e "$dir" ] || { echo "$0: $dir exists" >&2; exit 2; }

python3 -I -B -m venv "$dir"
"$dir/bin/python" -I -B -m pip install --no-input --disable-pip-version-check \
    --require-hashes --no-deps --only-binary :all: -r "$lock"
"$dir/bin/python" -I -B -m pip freeze --all
