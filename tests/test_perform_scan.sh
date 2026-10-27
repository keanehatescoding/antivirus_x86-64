#!/usr/bin/env bash
#
# tests/test_perform_scan.sh - characterization test for avd's scan
# pipeline (perform_scan() and the analyze_fd() half it wraps; see
# docs/privilege-separation.md, #103).
#
# Why this exists: the plan for #103 is to move the code that parses
# attacker-influenced file content (YARA, ssdeep, TLSH, SHA-256) out of
# root's address space. That needs the analysis step to stay exactly
# equivalent to what shipped before, and nothing else drove perform_scan()
# without the kernel module. This test includes userspace/avd/avd.c
# directly (main renamed) and runs each way a scan can end - signature,
# YARA override, YARA score threshold, below-threshold YARA falling through
# to fuzzy, fuzzy only, TLSH only, no rules loaded, clean - then checks the
# verdict, rule name, score, inconclusive flag, whether the file was
# quarantined, the quarantine directory contents and the metrics counters.
#
# Pure userspace: no kernel module and no netlink. Needs the same build
# dependencies as avd itself (libnl-genl-3, yara, libfuzzy). The quarantine
# directory lives in a mktemp dir, which avd's directory-trust check
# requires to be owned by the running user; run it as the user you built
# with, no sudo needed:
#   tests/test_perform_scan.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD_DIR="$REPO_ROOT/userspace/avd"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_perform_scan.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked, via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/harness.c" <<'EOF'
/* Built and run by tests/test_perform_scan.sh only, not part of the
 * shipped avd binary. Includes avd.c so the static scan pipeline can be
 * driven directly. */
#define _GNU_SOURCE
#define main avd_real_main
#include "avd.c"
#undef main

#include <fuzzy.h>

static void gen(const char *path, unsigned seed, size_t n, const char *marker) {
  FILE *f = fopen(path, "w");
  static const char *words[] = {"alpha", "bravo", "charlie", "delta", "echo",
                                "foxtrot", "golf", "hotel", "india", "juliet",
                                "kilo", "lima", "mike", "november", "oscar",
                                "papa", "quebec", "romeo", "sierra", "tango"};
  size_t i;

  if (!f) {
    perror(path);
    exit(2);
  }
  if (marker)
    fprintf(f, "%s\n", marker);
  for (i = 0; i < n; i++) {
    seed = seed * 1103515245u + 12345u;
    fprintf(f, "%s%u ", words[(seed >> 16) % 20], (seed >> 8) & 0xff);
    if (i % 12 == 11)
      fputc('\n', f);
  }
  fclose(f);
}

static void write_file(const char *path, const char *s) {
  FILE *f = fopen(path, "w");
  if (!f) {
    perror(path);
    exit(2);
  }
  fputs(s, f);
  fclose(f);
}

static void run_case(const char *label, const char *path, bool with_hash) {
  struct scan_result r;
  char sha[65] = "";
  int fd = open(path, O_RDONLY);

  if (fd < 0) {
    printf("CASE %s open-failed\n", label);
    return;
  }
  if (with_hash)
    sha256_fd(fd, sha);
  lseek(fd, 0, SEEK_SET);
  memset(&r, 0xAA, sizeof(r)); /* perform_scan must initialise everything */
  perform_scan(fd, path, with_hash ? sha : NULL, with_hash ? 1234 : 0,
               !with_hash, &r);
  close(fd);
  printf("CASE %s verdict=%u rule=\"%s\" score=%d sha=%s inconclusive=%d "
         "still_at_path=%d\n",
         label, r.verdict, r.rule_name, r.score, r.sha256_hex,
         (int)r.inconclusive, access(path, F_OK) == 0);
  fflush(stdout);
}

static void count_quarantine(const char *dir) {
  DIR *d = opendir(dir);
  struct dirent *e;
  int files = 0, metas = 0;

  if (!d) {
    printf("QDIR missing\n");
    return;
  }
  while ((e = readdir(d))) {
    size_t l = strlen(e->d_name);
    if (e->d_name[0] == '.')
      continue;
    if (l > 5 && !strcmp(e->d_name + l - 5, ".meta"))
      metas++;
    else
      files++;
  }
  closedir(d);
  printf("QDIR files=%d metas=%d\n", files, metas);
}

int main(int argc, char **argv) {
  char p[PATH_MAX], rules[PATH_MAX], qdir[PATH_MAX], fz[PATH_MAX],
      tl[PATH_MAX], hash[512], sha[65];
  const char *w;
  int fd;
  FILE *f;

  if (argc != 3) {
    fprintf(stderr, "usage: %s workdir clean-sample-file\n", argv[0]);
    return 2;
  }
  w = argv[1];
  snprintf(rules, sizeof(rules), "%s/rules", w);
  snprintf(qdir, sizeof(qdir), "%s/q", w);
  snprintf(fz, sizeof(fz), "%s/fuzzy.txt", w);
  snprintf(tl, sizeof(tl), "%s/tlsh.txt", w);
  mkdir(rules, 0700);

  /* Rules: an override rule, two weights that sum past the threshold, and
   * a weak one that stays below it. */
  snprintf(p, sizeof(p), "%s/t.yar", rules);
  write_file(p,
             "rule T_Override { meta: weight = 10 override = true\n"
             "  strings: $a = \"MARK_OVERRIDE\" condition: $a }\n"
             "rule T_Sum_A { meta: weight = 60 strings: $a = \"MARK_SUM\" "
             "condition: $a }\n"
             "rule T_Sum_B { meta: weight = 60 strings: $a = \"MARK_SUM\" "
             "condition: $a }\n"
             "rule T_Weak { meta: weight = 10 strings: $a = \"MARK_WEAK\" "
             "condition: $a }\n");

  /* A genuinely clean sample must not be statistically close to the
   * generated corpus entries below, or TLSH legitimately convicts it. */
  snprintf(p, sizeof(p), "%s/clean.txt", w);
  {
    FILE *in = fopen(argv[2], "r"), *out = fopen(p, "w");
    char buf[4096];
    size_t n;
    if (!in || !out) {
      perror("clean sample");
      return 2;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
      fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
  }
  snprintf(p, sizeof(p), "%s/override.txt", w);
  gen(p, 2, 300, "MARK_OVERRIDE");
  snprintf(p, sizeof(p), "%s/sum.txt", w);
  gen(p, 3, 300, "MARK_SUM");
  snprintf(p, sizeof(p), "%s/weak.txt", w);
  gen(p, 4, 300, "MARK_WEAK");
  snprintf(p, sizeof(p), "%s/weakfuzzy.txt", w);
  gen(p, 5, 3000, "MARK_WEAK");
  snprintf(p, sizeof(p), "%s/fuzzy.txt.bin", w);
  gen(p, 6, 3000, NULL);
  snprintf(p, sizeof(p), "%s/tlshfile.txt", w);
  gen(p, 7, 3000, NULL);
  snprintf(p, sizeof(p), "%s/sigfile.txt", w);
  gen(p, 8, 400, NULL);
  snprintf(p, sizeof(p), "%s/norules.txt", w);
  gen(p, 9, 400, NULL);
  snprintf(p, sizeof(p), "%s/tiny.txt", w);
  write_file(p, "hi\n");

  /* Fuzzy corpus: weakfuzzy.txt and fuzzy.txt.bin */
  f = fopen(fz, "w");
  snprintf(p, sizeof(p), "%s/weakfuzzy.txt", w);
  if (fuzzy_hash_filename(p, hash) != 0) {
    fprintf(stderr, "fuzzy hash failed\n");
    return 2;
  }
  fprintf(f, "%s,TestWeakFuzzy\n", hash);
  snprintf(p, sizeof(p), "%s/fuzzy.txt.bin", w);
  if (fuzzy_hash_filename(p, hash) != 0)
    return 2;
  fprintf(f, "%s,TestFuzzy\n", hash);
  fclose(f);

  /* TLSH corpus */
  snprintf(p, sizeof(p), "%s/tlshfile.txt", w);
  fd = open(p, O_RDONLY);
  if (av_tlsh_hash_fd(fd, hash, sizeof(hash), MAX_FUZZY_TLSH_FILE_SIZE) != 0) {
    fprintf(stderr, "tlsh hash failed\n");
    return 2;
  }
  close(fd);
  f = fopen(tl, "w");
  fprintf(f, "%s,TestTlsh\n", hash);
  fclose(f);

  quarantine_dir = qdir;
  if (load_rules(rules) < 0 || !compiled_rules) {
    fprintf(stderr, "load_rules failed\n");
    return 2;
  }
  if (load_fuzzy_corpus(fz) < 0 || load_tlsh_corpus(tl) < 0) {
    fprintf(stderr, "corpus load failed\n");
    return 2;
  }

  /* Exact-signature snapshot for sigfile.txt (normally fanotify-only). */
  snprintf(p, sizeof(p), "%s/sigfile.txt", w);
  fd = open(p, O_RDONLY);
  sha256_fd(fd, sha);
  close(fd);
  fan_sigs = calloc(1, sizeof(*fan_sigs));
  memcpy(fan_sigs[0].hex, sha, 65);
  snprintf(fan_sigs[0].name, sizeof(fan_sigs[0].name), "TestSig");
  fan_sig_count = 1;

#define CASE(label, file, with_hash)                                           \
  do {                                                                         \
    snprintf(p, sizeof(p), "%s/%s", w, file);                                  \
    run_case(label, p, with_hash);                                             \
  } while (0)

  CASE("clean_ondemand", "clean.txt", false);
  CASE("clean_kernelhash", "clean.txt", true);
  CASE("tiny_clean", "tiny.txt", false);
  CASE("yara_override", "override.txt", false);
  CASE("yara_sum_over_threshold", "sum.txt", true);
  CASE("yara_weak_clean", "weak.txt", false);
  CASE("yara_weak_then_fuzzy", "weakfuzzy.txt", false);
  CASE("fuzzy_only", "fuzzy.txt.bin", true);
  CASE("tlsh_only", "tlshfile.txt", false);
  CASE("signature", "sigfile.txt", true);

  /* No rules loaded: fail open, inconclusive, nothing quarantined. */
  {
    YR_RULES *saved = compiled_rules;
    compiled_rules = NULL;
    CASE("no_rules", "norules.txt", false);
    compiled_rules = saved;
  }

  /* The convicted file is gone from its path, so opening it fails. */
  CASE("rescan_gone", "override.txt", false);

  count_quarantine(qdir);
  printf("METRICS scans_total=%llu scans_malicious=%llu\n",
         (unsigned long long)scans_total, (unsigned long long)scans_malicious);
  return 0;
}
EOF

# Same dependency probing as userspace/avd/Makefile.
PKG_CONFIG="${PKG_CONFIG:-pkg-config}"
if ! "$PKG_CONFIG" --exists libnl-genl-3.0 yara 2>/dev/null; then
    echo "FAIL: libnl-genl-3.0 and yara dev packages are required (see 'make -C userspace/avd checkdeps')"
    exit 1
fi
LIBS="$("$PKG_CONFIG" --libs libnl-genl-3.0 yara) $("$PKG_CONFIG" --libs fuzzy 2>/dev/null || echo -lfuzzy) -lpthread"
CFLAGS_PC="$("$PKG_CONFIG" --cflags libnl-genl-3.0 yara)"

# shellcheck disable=SC2086 # $CFLAGS_PC and $LIBS are intentionally word-split
if ! cc -Wall -Wextra -O2 -w -I"$AVD_DIR" $CFLAGS_PC \
        -o "$BUILD_DIR/harness" "$BUILD_DIR/harness.c" \
        "$AVD_DIR/sha256.c" "$AVD_DIR/tlsh_core.c" "$AVD_DIR/tlsh_shim.c" \
        $LIBS 2> "$BUILD_DIR/cc.log"; then
    echo "FAIL: could not build the harness:"
    cat "$BUILD_DIR/cc.log"
    exit 1
fi

WORK="$BUILD_DIR/work"
mkdir -p "$WORK"
# A real-text clean sample (numbers, not the generated word text above).
seq 1 5000 > "$BUILD_DIR/clean-sample.txt"

if ! "$BUILD_DIR/harness" "$WORK" "$BUILD_DIR/clean-sample.txt" \
        > "$BUILD_DIR/out.txt" 2> "$BUILD_DIR/err.txt"; then
    echo "FAIL: harness exited non-zero:"
    cat "$BUILD_DIR/err.txt"
    exit 1
fi

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Compare each CASE line with its sha= field removed (the digest is checked
# separately below), so the expectation table is independent of the clean
# sample's contents.
actual_case() {
    grep -F "CASE $1 " "$BUILD_DIR/out.txt" | sed -E 's/ sha=[0-9a-f]*//'
}

expect_case() {
    local label="$1" want="$2" got
    got="$(actual_case "$label")"
    if [ "$got" = "CASE $label $want" ]; then
        pass "$label"
    else
        fail "$label"
        echo "    want: CASE $label $want"
        echo "    got:  $got"
    fi
}

echo "scan outcomes:"
expect_case clean_ondemand            'verdict=0 rule="" score=0 inconclusive=0 still_at_path=1'
expect_case clean_kernelhash          'verdict=0 rule="" score=0 inconclusive=0 still_at_path=1'
expect_case tiny_clean                'verdict=0 rule="" score=0 inconclusive=0 still_at_path=1'
expect_case yara_override             'verdict=1 rule="T_Override" score=10 inconclusive=0 still_at_path=0'
expect_case yara_sum_over_threshold   'verdict=1 rule="T_Sum_A,T_Sum_B" score=120 inconclusive=0 still_at_path=0'
expect_case yara_weak_clean           'verdict=0 rule="" score=10 inconclusive=0 still_at_path=1'
expect_case yara_weak_then_fuzzy      'verdict=1 rule="Fuzzy:TestWeakFuzzy(100)" score=10 inconclusive=0 still_at_path=0'
expect_case fuzzy_only                'verdict=1 rule="Fuzzy:TestFuzzy(100)" score=0 inconclusive=0 still_at_path=0'
expect_case tlsh_only                 'verdict=1 rule="TLSH:TestTlsh(0)" score=0 inconclusive=0 still_at_path=0'
expect_case signature                 'verdict=1 rule="Sig:TestSig" score=0 inconclusive=0 still_at_path=0'
expect_case no_rules                  'verdict=0 rule="" score=0 inconclusive=1 still_at_path=1'

echo "quarantine and metrics:"
if grep -qx 'CASE rescan_gone open-failed' "$BUILD_DIR/out.txt"; then
    pass "convicted file no longer at its original path"
else
    fail "convicted file no longer at its original path"
fi
# Six convictions: yara_override, yara_sum, weak_then_fuzzy, fuzzy_only,
# tlsh_only, signature - each leaves exactly one file plus one sidecar.
if grep -qx 'QDIR files=6 metas=6' "$BUILD_DIR/out.txt"; then
    pass "6 quarantined files, 6 sidecars"
else
    fail "6 quarantined files, 6 sidecars ($(grep '^QDIR' "$BUILD_DIR/out.txt"))"
fi
if grep -qx 'METRICS scans_total=11 scans_malicious=6' "$BUILD_DIR/out.txt"; then
    pass "metrics: 11 scans, 6 malicious"
else
    fail "metrics: 11 scans, 6 malicious ($(grep '^METRICS' "$BUILD_DIR/out.txt"))"
fi

echo "digests:"
bad_sha="$(grep '^CASE .* sha=' "$BUILD_DIR/out.txt" | sed -E 's/.* sha=([0-9a-f]*) .*/\1/' | grep -vcE '^[0-9a-f]{64}$')"
if [ "$bad_sha" = "0" ]; then
    pass "every scan reports a 64-hex SHA-256"
else
    fail "$bad_sha scan(s) reported a missing or malformed SHA-256"
fi
want_sha="$(sha256sum "$BUILD_DIR/clean-sample.txt" | cut -d' ' -f1)"
for c in clean_ondemand clean_kernelhash; do
    got_sha="$(grep -F "CASE $c " "$BUILD_DIR/out.txt" | sed -E 's/.* sha=([0-9a-f]*) .*/\1/')"
    if [ "$got_sha" = "$want_sha" ]; then
        pass "$c digest matches sha256sum"
    else
        fail "$c digest matches sha256sum (got $got_sha)"
    fi
done

echo "log output:"
# The acting half (quarantine) runs after the analysis half has logged its
# verdict, so each QUARANTINED line must follow the matching match line.
if awk '
    /SIGNATURE MATCH|avd: MATCH |FUZZY MATCH|TLSH MATCH/ { pending = 1; next }
    /QUARANTINED/ { if (!pending) bad++; pending = 0 }
    END { exit bad ? 1 : 0 }' "$BUILD_DIR/out.txt"; then
    pass "every QUARANTINED line is preceded by its match line"
else
    fail "a QUARANTINED line appeared without a preceding match line"
fi

echo
echo "perform_scan: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
