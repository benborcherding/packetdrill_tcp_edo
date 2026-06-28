#!/bin/sh
# Run the TCP EDO .pkt integration suite on the FreeBSD EDO kernel VM.
#
# EDO tests must run inside the modified FreeBSD kernel (e.g. a UTM VM), not on
# the host. This script syncs the packetdrill source to the VM, builds it there,
# then runs every .pkt under a target directory as root and prints a PASS/FAIL
# summary. Failing tests are retried a few times first, because the very first
# run after a cold VM boot can hit a packetdrill timing tolerance unrelated to
# EDO (see README.md, edo-1 note).
#
# Self-contained: it only needs rsync + ssh and an ssh alias for the VM.
#
# Prereqs: the VM is provisioned with the EDO kernel and reachable via the ssh
# alias in $FBSD_VM (default 'fbsd-edo'), with key-auth + NOPASSWD sudo so
# nothing prompts interactively.
#
# Usage (from anywhere):
#   scripts/run_vm.sh                                 # full EDO suite
#   scripts/run_vm.sh tests/bsd/tcp/edo/edo-3-options-over-60.pkt
#   SKIP_BUILD=1 scripts/run_vm.sh                    # skip sync+build (faster)
#   RETRIES=5 scripts/run_vm.sh                       # retries per test (def 3)
#
# Config via env: FBSD_VM (ssh alias), FBSD_DEST (path in VM, rel. to home),
# RETRIES, SKIP_BUILD.
set -eu

VM="${FBSD_VM:-fbsd-edo}"
DEST="${FBSD_DEST:-packetdrill}"
RETRIES="${RETRIES:-3}"
TARGET="${1:-tests/bsd/tcp/edo}"

# packetdrill source root, relative to this script at <repo>/scripts/run_vm.sh.
SRC_DIR="$(cd "$(dirname "$0")/../gtests/net/packetdrill" && pwd)/"

if [ "${SKIP_BUILD:-0}" = "1" ]; then
	printf '>>> SKIP_BUILD=1: using the existing build on %s\n' "$VM"
else
	printf '>>> Syncing source -> %s:%s ...\n' "$VM" "$DEST"
	# Honour .gitignore so host build artifacts (*.o, generated parser.c/
	# lexer.c, binaries) stay on the host; the VM regenerates and rebuilds.
	rsync -az --delete --filter=':- .gitignore' "$SRC_DIR" "$VM:$DEST/"
	printf '>>> Building on %s ...\n' "$VM"
	ssh "$VM" "cd '$DEST' && ./configure >/dev/null && make >/dev/null 2>&1" \
		|| { echo ">>> BUILD FAILED" >&2; exit 1; }
	printf '>>> Build OK\n'
fi

printf '>>> Running suite under: %s (retries: %s)\n\n' "$TARGET" "$RETRIES"

ssh "$VM" "cd '$DEST' && RETRIES='$RETRIES' TARGET='$TARGET' sh -s" <<'REMOTE'
set -u
if [ -d "$TARGET" ]; then
	files=$(ls "$TARGET"/*.pkt 2>/dev/null)
else
	files="$TARGET"
fi
[ -n "$files" ] || { echo "no .pkt files under $TARGET" >&2; exit 2; }

pass=0; fail=0; failed_list=""
for f in $files; do
	name=$(basename "$f")
	out=""; ok=0; i=1
	while [ "$i" -le "$RETRIES" ]; do
		out=$(sudo ./packetdrill "$f" 2>&1) && { ok=1; break; }
		i=$((i + 1))
	done
	if [ "$ok" -eq 1 ]; then
		if [ "$i" -gt 1 ]; then
			printf 'PASS  %s  (after %s tries)\n' "$name" "$i"
		else
			printf 'PASS  %s\n' "$name"
		fi
		pass=$((pass + 1))
	else
		printf 'FAIL  %s\n' "$name"
		printf '%s\n' "$out" | sed 's/^/        /' | head -8
		fail=$((fail + 1))
		failed_list="$failed_list $name"
	fi
done

printf '\n=== %s passed, %s failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || { printf 'failed:%s\n' "$failed_list"; exit 1; }
REMOTE
