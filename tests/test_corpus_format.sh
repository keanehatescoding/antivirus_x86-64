#!/usr/bin/env bash
#
# tests/test_corpus_format.sh - load-time validation of the fuzzy/TLSH
# corpus files by userspace/avd/avd.c (load_fuzzy_corpus() /
# load_tlsh_corpus(), issue #104).
#
# Malformed corpus entries used to be stored silently: any "<hash>,<name>"
# line with a comma passed the shape check, so a typo'd hash sat in the
# corpus matching nothing on every scan (fuzzy_compare() scores
# unparseable input -1, av_tlsh_diff() returns -1) with no startup
# warning. The loaders now self-check each hash through the same parse
# path the scan uses (fuzzy_compare(h, h) must be 100, av_tlsh_diff(h, h)
# must be 0) and skip loudly otherwise.
#
# Pure userspace, no kernel module or root needed: avd loads rules and
# both corpora BEFORE resolving the "av_genl" netlink family, so it
# prints the loader diagnostics and then fail-fasts on the missing
# module - that expected genl failure is what proves the run actually
# reached past the loaders. Safe to run standalone:
#   tests/test_corpus_format.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD="$REPO_ROOT/userspace/avd/avd"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_corpus.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

PASS=0
FAIL=0

check() {
    # check <description> <fixed-string> <file>: PASS if present.
    if grep -qF "$2" "$3"; then
        echo "PASS: $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $1 (missing: $2)"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    # check_absent <description> <fixed-string> <file>: PASS if absent.
    if grep -qF "$2" "$3"; then
        echo "FAIL: $1 (unexpected: $2)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS: $1"
        PASS=$((PASS + 1))
    fi
}

echo "### building avd ###"
if ! make -C "$REPO_ROOT/userspace/avd" >/dev/null 2>&1; then
    echo "FAIL: avd build failed"
    exit 1
fi

QUAR="$BUILD_DIR/quarantine"
SOCK="$BUILD_DIR/control.sock"
mkdir -p "$QUAR"

# Mixed corpora: one valid entry each (the shipped test-fixture hashes,
# verbatim) plus one malformed entry per failure shape.
cat > "$BUILD_DIR/fuzzy.txt" <<'EOF'
# comment and blank lines still ignored

96:R5d5Aq+TRB+B7YSYGtD35nw7/QBfxBpviOsM6:Rf+NwZSgpwEn/viD,good-fuzzy
notahash,bad-no-colons
96:abc,bad-short
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,bad-overlong
EOF

cat > "$BUILD_DIR/tlsh.txt" <<'EOF'
2C722243F7B0C93FCC6C537C406B477AA2F3E92043624327AB4466682E9369C5E67D96,good-tlsh
ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ,bad-hex
2C72,bad-short
2C722243F7B0C93FCC6C537C406B477AA2F3E92043624327AB4466682E9369C5E67D96001,bad-overlong
T12C722243F7B0C93FCC6C537C406B477AA2F3E92043624327AB4466682E9369C5E67D9,bad-prefix
EOF

"$AVD" "$REPO_ROOT/rules" "$BUILD_DIR/fuzzy.txt" "$QUAR" \
    "$BUILD_DIR/tlsh.txt" "$SOCK" > "$BUILD_DIR/mixed.log" 2>&1
STATUS=$?

echo "### mixed corpora: malformed entries rejected loudly ###"
if [ "$STATUS" -eq 0 ]; then
    echo "FAIL: avd exited 0 without the kernel module (expected genl fail-fast)"
    FAIL=$((FAIL + 1))
else
    echo "PASS: avd fail-fasts past the loaders without the module (exit $STATUS)"
    PASS=$((PASS + 1))
fi
check "genl fail-fast proves loaders ran" 'could not resolve family "av_genl"' "$BUILD_DIR/mixed.log"
check "fuzzy typo rejected" \
    "avd: skipping malformed fuzzy corpus line (hash fails to parse): bad-no-colons" \
    "$BUILD_DIR/mixed.log"
check "fuzzy truncated hash rejected" \
    "avd: skipping malformed fuzzy corpus line (hash fails to parse): bad-short" \
    "$BUILD_DIR/mixed.log"
check "fuzzy overlong hash rejected before truncation" \
    "avd: skipping malformed fuzzy corpus line (hash fails to parse): bad-overlong" \
    "$BUILD_DIR/mixed.log"
check "TLSH non-hex rejected" \
    "avd: skipping malformed TLSH corpus line (hash is not a 70-char hex digest): bad-hex" \
    "$BUILD_DIR/mixed.log"
check "TLSH short hash rejected" \
    "avd: skipping malformed TLSH corpus line (hash is not a 70-char hex digest): bad-short" \
    "$BUILD_DIR/mixed.log"
check "TLSH overlong hash rejected" \
    "avd: skipping malformed TLSH corpus line (hash is not a 70-char hex digest): bad-overlong" \
    "$BUILD_DIR/mixed.log"
check "TLSH T1-prefixed hash rejected" \
    "avd: skipping malformed TLSH corpus line (hash is not a 70-char hex digest): bad-prefix" \
    "$BUILD_DIR/mixed.log"
check "only the valid fuzzy entry loads" \
    "avd: loaded 1 fuzzy hash(es) from $BUILD_DIR/fuzzy.txt" \
    "$BUILD_DIR/mixed.log"
check "only the valid TLSH entry loads" \
    "avd: loaded 1 TLSH hash(es) from $BUILD_DIR/tlsh.txt" \
    "$BUILD_DIR/mixed.log"

echo "### shipped corpora: no regression on valid format ###"
"$AVD" "$REPO_ROOT/rules" "$REPO_ROOT/corpus/fuzzy_hashes.txt" "$QUAR" \
    "$REPO_ROOT/corpus/tlsh_hashes.txt" "$SOCK" > "$BUILD_DIR/clean.log" 2>&1
check_absent "no fuzzy skip warnings on shipped corpus" \
    "skipping malformed fuzzy" "$BUILD_DIR/clean.log"
check_absent "no TLSH skip warnings on shipped corpus" \
    "skipping malformed TLSH" "$BUILD_DIR/clean.log"
check "shipped fuzzy fixture still loads" \
    "avd: loaded 1 fuzzy hash(es) from $REPO_ROOT/corpus/fuzzy_hashes.txt" \
    "$BUILD_DIR/clean.log"
check "shipped TLSH fixture still loads" \
    "avd: loaded 1 TLSH hash(es) from $REPO_ROOT/corpus/tlsh_hashes.txt" \
    "$BUILD_DIR/clean.log"
# Fixture-only corpora must warn at startup (#99): packaged installs
# never show make install's echo, but every install runs these
# loaders, so this stderr line is the channel that reaches real users
# via the journal. The mixed corpora above carry non-fixture names
# (good-fuzzy/good-tlsh), so they must NOT trigger it.
check "shipped fuzzy corpus warns it is fixture-only" \
    "fuzzy corpus \"$REPO_ROOT/corpus/fuzzy_hashes.txt\" contains only the demo fixture sample" \
    "$BUILD_DIR/clean.log"
check "shipped TLSH corpus warns it is fixture-only" \
    "TLSH corpus \"$REPO_ROOT/corpus/tlsh_hashes.txt\" contains only the demo fixture sample" \
    "$BUILD_DIR/clean.log"
check_absent "non-fixture corpus does not warn" \
    "contains only the demo fixture sample" "$BUILD_DIR/mixed.log"

echo
echo "test_corpus_format.sh: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
