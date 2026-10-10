#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_dynamic_symbol_evasion.sh - v0.9.0 evasion test 1.
#
# Technique: resolve ptrace() via dlopen()+dlsym() at runtime instead of
# linking it directly. This removes the direct dynamic-symbol-table
# entry that rules/heuristics.yar's Imports_Ptrace rule checks for
# (elf.dynsym), while the actual behavior (calling ptrace) is identical.
#
# Runs standalone - no kernel module needed, just the yara CLI.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULES="$REPO_ROOT/rules/heuristics.yar"

echo "=== Evasion test: dynamic symbol resolution (dlopen/dlsym) ==="

# Private mktemp -d, not fixed /tmp/dynsym_evasion.* paths: predictable
# world-writable-directory names let another local user pre-plant a symlink
# that this script's compiler output would then follow. Same pattern as
# tests/test_netlink.sh.
EVASION_TMP_DIR="$(mktemp -d -- /tmp/dynsym_evasion.XXXXXX)" || exit 1
trap 'rm -rf "$EVASION_TMP_DIR"' EXIT

cat > "$EVASION_TMP_DIR/dynsym_evasion.c" << 'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>

int main(void) {
    void *libc = dlopen("libc.so.6", RTLD_LAZY);
    long (*ptrace_fn)(int, pid_t, void *, void *);

    if (!libc) {
        fprintf(stderr, "dlopen failed\n");
        return 1;
    }

    ptrace_fn = dlsym(libc, "ptrace");
    if (ptrace_fn)
        ptrace_fn(16 /* PTRACE_ATTACH */, 1234, NULL, NULL);

    printf("done\n");
    return 0;
}
EOF
gcc -o "$EVASION_TMP_DIR/dynsym_evasion" "$EVASION_TMP_DIR/dynsym_evasion.c" -ldl

echo
echo "--- dynamic symbol table (confirming ptrace is NOT a direct import) ---"
objdump -T "$EVASION_TMP_DIR/dynsym_evasion" | grep -i ptrace && \
    echo "UNEXPECTED: ptrace found as a direct import - evasion technique failed to build correctly" || \
    echo "confirmed: no direct ptrace import (as intended)"

echo
echo "--- running heuristics.yar ---"
MATCHES="$(yara "$RULES" "$EVASION_TMP_DIR/dynsym_evasion" || true)"
echo "$MATCHES"

echo
if echo "$MATCHES" | grep -q "^Imports_Ptrace"; then
    echo "RESULT: Imports_Ptrace still fired - evasion FAILED"
    exit 1
else
    echo "RESULT: Imports_Ptrace evaded successfully"
    if echo "$MATCHES" | grep -q "^Imports_Dlopen"; then
        echo "  (but Imports_Dlopen fired instead - the evasion TECHNIQUE itself"
        echo "   is a weak signal, even though the specific API it hides is not)"
    fi
fi
