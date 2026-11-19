#!/bin/bash
# demo/framework/install-venv.sh — create the agent's venv, once, as root.
#
#   sudo demo/framework/install-venv.sh
#
# Creates /opt/anchorstamp-venv with the system python3 and installs
# exactly demo/framework/requirements.lock into it: every file checked
# against its pinned sha256 (--require-hashes), no dependency resolution
# (--no-deps), binary wheels only, so no package code runs at install.
# Then everything under it is made root:root and not group- or
# other-writable, so the measured account can read and execute it but
# change nothing. Prints what it did; capture the output as its log.
#
# The lock sits in a tree the operator owns, so it is copied once, through
# one descriptor, into a root-owned 0600 file in a root-owned 0700
# temporary directory; the copy must hold nothing but pinned requirements
# and their hashes, and only the copy is installed from.
#
# Refuses if /opt/anchorstamp-venv exists in any form. It never removes or
# overwrites anything but its own temporary copy of the lock; to rebuild,
# the operator removes the venv first.
set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

VENV=/opt/anchorstamp-venv
HERE=$(cd "$(dirname "$0")" && pwd -P)
LOCK=$HERE/requirements.lock

say() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() {
    say "REFUSED: $*"
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "not root"
if [ -e "$VENV" ] || [ -L "$VENV" ]; then die "$VENV exists; this script never replaces it"; fi
if [ ! -f "$LOCK" ] || [ -L "$LOCK" ]; then die "$LOCK is not a regular file"; fi
python3 -I -B -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "python3 is older than 3.10"

say "python3: $(python3 -I -B -c 'import sys; print(sys.version.split()[0])') at $(readlink -f "$(command -v python3)")"

# the lock: copied through one descriptor that must name the file checked
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
[ "$(stat -c '%u:%g %a' "$TMP")" = "0:0 700" ] || die "$TMP is not root:root 0700"
COPY=$TMP/requirements.lock
exec {fd}<"$LOCK" || die "$LOCK cannot be opened"
seen=$(stat -c '%F %d:%i' -- "$LOCK")
held=$(stat -L -c '%F %d:%i' "/proc/self/fd/$fd")
if [ -L "$LOCK" ] || [ "$seen" != "$held" ]; then die "$LOCK changed while being opened"; fi
case "$held" in "regular file "*) ;; *) die "$LOCK is not a regular file" ;; esac
(umask 077 && cat <&"$fd" >"$COPY") || die "copying $LOCK failed"
exec {fd}<&-
chown root:root "$COPY"
chmod 0600 "$COPY"
[ "$(stat -c '%u:%g %a' "$COPY")" = "0:0 600" ] || die "$COPY is not root:root 0600"
# no NUL byte (grep would treat the file as binary); then every line:
# blank, a comment, name==version, or a sha256 hash continuation
[ "$(tr -d '\000' <"$COPY" | wc -c)" -eq "$(wc -c <"$COPY")" ] || die "$LOCK contains a NUL byte"
BAD=$(grep -navE '^[[:space:]]*(#.*)?$|^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.+!_-]*( \\)?$|^[[:space:]]+--hash=sha256:[0-9a-f]{64}( \\)?$' "$COPY" | head -n3) || true
[ -z "$BAD" ] || die "$LOCK holds a line that is not a pinned requirement or a hash: $BAD"
say "lock: copied from $LOCK; copy sha256 $(sha256sum "$COPY" | cut -d' ' -f1)"

say "creating $VENV"
python3 -I -B -m venv "$VENV"
say "installing the lock"
"$VENV/bin/python" -I -B -m pip install --no-input --disable-pip-version-check --no-cache-dir \
    --require-hashes --no-deps --only-binary :all: -r "$COPY"

chown -R root:root "$VENV"
chmod -R go-w "$VENV"

BAD=$(find "$VENV" \( ! -uid 0 -o ! -gid 0 \) -print -quit)
[ -z "$BAD" ] || die "entry not owned by root:root: $BAD"
BAD=$(find "$VENV" ! -type l -perm /022 -print -quit)
[ -z "$BAD" ] || die "entry writable by group or other: $BAD"
say "ownership: root:root throughout; nothing group- or other-writable"
say "done"
