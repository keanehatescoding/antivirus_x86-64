#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_fuzzy_evasion.sh - v0.9.0 evasion test 2.
#
# Technique: fuzzy hashing (ssdeep/CTPH) tolerates MINOR modifications
# (a few appended bytes score ~100 similarity, per the v0.7.0 testing
# section) but this tests whether SUBSTANTIAL modification defeats it
# entirely - appending a large amount of data relative to the original
# file size.
#
# Runs standalone - no kernel module needed, just ssdeep/libfuzzy.
#
set -euo pipefail

# Same libfuzzy link flags as userspace/avd/Makefile's FUZZY_LIBS:
# honor a packager-provided override (e.g. FUZZY_LIBS="-l:libfuzzy.a"
# ./tests/evasion/test_fuzzy_evasion.sh) so environments where plain
# -lfuzzy doesn't link still work here, and otherwise probe pkg-config
# with the same plain -lfuzzy fallback the daemon build uses. Resolved
# through PKG_CONFIG (not a hardcoded pkg-config), mirroring the
# Makefile's `PKG_CONFIG ?=` so a target-specific wrapper applies here
# too.
PKG_CONFIG="${PKG_CONFIG:-pkg-config}"
FUZZY_LIBS="${FUZZY_LIBS:-$("$PKG_CONFIG" --libs fuzzy 2>/dev/null || echo "-lfuzzy")}"

echo "=== Evasion test: fuzzy hash evasion via substantial modification ==="

# Private mktemp -d, not fixed /tmp/ptrace_test* paths (see
# test_dynamic_symbol_evasion.sh for why predictable /tmp names are a
# symlink-planting target).
EVASION_TMP_DIR="$(mktemp -d -- /tmp/fuzzy_evasion.XXXXXX)" || exit 1
trap 'rm -rf "$EVASION_TMP_DIR"' EXIT

if [ ! -f "$EVASION_TMP_DIR/ptrace_test" ]; then
    cat > "$EVASION_TMP_DIR/ptrace_test.c" << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
    gcc -o "$EVASION_TMP_DIR/ptrace_test" "$EVASION_TMP_DIR/ptrace_test.c"
fi

ssdeep -b "$EVASION_TMP_DIR/ptrace_test" > "$EVASION_TMP_DIR/corpus_seed.txt"

echo
echo "--- baseline: minor modification (few bytes appended) ---"
cp "$EVASION_TMP_DIR/ptrace_test" "$EVASION_TMP_DIR/minor_variant"
echo "small change" >> "$EVASION_TMP_DIR/minor_variant"
ssdeep -m "$EVASION_TMP_DIR/corpus_seed.txt" "$EVASION_TMP_DIR/minor_variant" || echo "(no match - unexpected for a minor variant)"

echo
echo "--- evasion attempt: substantial modification (+50KB random data," \
     "original file is ~16KB) ---"
cp "$EVASION_TMP_DIR/ptrace_test" "$EVASION_TMP_DIR/heavy_variant"
head -c 50000 /dev/urandom >> "$EVASION_TMP_DIR/heavy_variant"

RESULT="$(ssdeep -m "$EVASION_TMP_DIR/corpus_seed.txt" "$EVASION_TMP_DIR/heavy_variant" || true)"
if [ -n "$RESULT" ]; then
    echo "$RESULT"
    echo
    echo "RESULT: still matched - evasion FAILED"
else
    echo "(no match reported)"
    echo
    echo "RESULT: fuzzy hash evaded successfully"
fi

echo
echo "--- exact similarity score (via libfuzzy C API, same as avd.c uses) ---"
cat > "$EVASION_TMP_DIR/fuzzy_score_check.c" << 'EOF'
#include <stdio.h>
#include <fuzzy.h>
int main(int argc, char **argv) {
    char h1[FUZZY_MAX_RESULT], h2[FUZZY_MAX_RESULT];
    fuzzy_hash_filename(argv[1], h1);
    fuzzy_hash_filename(argv[2], h2);
    printf("similarity score: %d/100\n", fuzzy_compare(h1, h2));
    return 0;
}
EOF
# Word-split FUZZY_LIBS deliberately: it may hold several flags
# (e.g. "-L/opt/ssdeep/lib -l:libfuzzy.a").
# shellcheck disable=SC2086
gcc -o "$EVASION_TMP_DIR/fuzzy_score_check" "$EVASION_TMP_DIR/fuzzy_score_check.c" $FUZZY_LIBS
"$EVASION_TMP_DIR/fuzzy_score_check" "$EVASION_TMP_DIR/ptrace_test" "$EVASION_TMP_DIR/heavy_variant"
