#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_entropy_dilution_evasion.sh - v0.9.0 evasion test 3.
#
# Technique: pad a packed (high-entropy) binary with a large amount of
# low-entropy filler (zero bytes) to dilute the WHOLE-FILE Shannon
# entropy average below the 7.0 threshold.
#
# The interesting question isn't just "does this evade entropy.yar" -
# it's "does evading ONE layer mean evading the whole engine", since
# this project's design is explicitly layered (v0.3.0-v0.8.0 are
# separate, independent checks). This test checks BOTH.
#
# Runs standalone - no kernel module needed, just the yara CLI + upx.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "=== Evasion test: entropy dilution (padding a packed binary) ==="

# Private mktemp -d, not fixed /tmp/ptrace_test* paths (see
# test_dynamic_symbol_evasion.sh for why predictable /tmp names are a
# symlink-planting target).
EVASION_TMP_DIR="$(mktemp -d -- /tmp/entropy_evasion.XXXXXX)" || exit 1
trap 'rm -rf "$EVASION_TMP_DIR"' EXIT

if [ ! -f "$EVASION_TMP_DIR/ptrace_test" ]; then
    cat > "$EVASION_TMP_DIR/ptrace_test.c" << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
    gcc -o "$EVASION_TMP_DIR/ptrace_test" "$EVASION_TMP_DIR/ptrace_test.c"
fi

if ! command -v upx >/dev/null 2>&1; then
    echo "upx not installed - install upx-ucl (apt) or upx (pacman) to run this test"
    exit 1
fi

upx --best -o "$EVASION_TMP_DIR/upx_packed_evasion" "$EVASION_TMP_DIR/ptrace_test" >/dev/null 2>&1

echo
echo "--- baseline: packed binary, unmodified ---"
yara "$REPO_ROOT/rules/entropy.yar" "$EVASION_TMP_DIR/upx_packed_evasion"
echo "(expect: High_Overall_Entropy)"

echo
echo "--- evasion attempt: pad with 500KB of zero bytes ---"
cp "$EVASION_TMP_DIR/upx_packed_evasion" "$EVASION_TMP_DIR/entropy_evasion"
head -c 500000 /dev/zero >> "$EVASION_TMP_DIR/entropy_evasion"

ENTROPY_RESULT="$(yara "$REPO_ROOT/rules/entropy.yar" "$EVASION_TMP_DIR/entropy_evasion" || true)"
if echo "$ENTROPY_RESULT" | grep -q High_Overall_Entropy; then
    echo "entropy.yar: still fired - entropy evasion FAILED"
    ENTROPY_EVADED=0
else
    echo "entropy.yar: no match - entropy check evaded"
    ENTROPY_EVADED=1
fi

echo
echo "--- but does the STRUCTURAL check (elf_analysis.yar) still catch it? ---"
STRUCT_RESULT="$(yara "$REPO_ROOT/rules/elf_analysis.yar" "$EVASION_TMP_DIR/entropy_evasion" || true)"
echo "$STRUCT_RESULT"

echo
if [ "$ENTROPY_EVADED" -eq 1 ] && echo "$STRUCT_RESULT" | grep -q .; then
    echo "RESULT: entropy check evaded, BUT structural rules still caught the"
    echo "same file - defense-in-depth held. Evading one layer of a layered"
    echo "detection engine is not the same as evading the engine."
elif [ "$ENTROPY_EVADED" -eq 1 ]; then
    echo "RESULT: entropy check evaded AND no other rule caught it either -"
    echo "genuine full evasion of this sample."
else
    echo "RESULT: entropy dilution did not work as expected."
fi
