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

/* HARNESS_STRESS=1: several threads, each owning one worker, scanning a clean
 * file far more often than AVD_PRIVSEP_MAX_SCANS so every thread recycles its
 * worker. Counts scans that were not a clean conclusive result and how often
 * each thread's worker pid changed. */
struct stress_arg {
  const char *path;
  int scans;
  int bad;
  int pid_changes;
};

static void *stress_thread(void *a) {
  struct stress_arg *s = a;
  pid_t last = 0;

  for (int i = 0; i < s->scans; i++) {
    struct scan_result r;
    int fd = open(s->path, O_RDONLY);

    if (fd < 0) {
      s->bad++;
      continue;
    }
    perform_scan(fd, s->path, NULL, 0, true, &r);
    close(fd);
    if (r.verdict != AV_VERDICT_CLEAN || r.inconclusive)
      s->bad++;
    if (privsep_w.pid != last) {
      if (last)
        s->pid_changes++;
      last = privsep_w.pid;
    }
  }
  privsep_release_thread_worker();
  return NULL;
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

  /* HARNESS_PRIVSEP=1: run the same cases with the content analysis in
   * unprivileged workers, started the way avd's main() starts them (after
   * the rules and corpora are loaded, while still single-threaded). 65534 is
   * nobody, as in the spawner and client tests. Needs root; the shell side
   * only sets this when it is root. */
  if (getenv("HARNESS_PRIVSEP")) {
    if (privsep_start(65534, 65534) != 0) {
      fprintf(stderr, "privsep_start failed\n");
      return 2;
    }
    /* HARNESS_KILL_SPAWNER=1: lose the spawner before any scan. avd must
     * exit (privsep_on_dead) rather than scan the cases itself as root. */
    if (getenv("HARNESS_KILL_SPAWNER")) {
      kill(privsep_cl.spawner_pid, SIGKILL);
      sleep(2);
    }
    if (getenv("HARNESS_STRESS")) {
      enum { THREADS = 4, SCANS = 600 };
      pthread_t t[THREADS];
      struct stress_arg a[THREADS];
      int bad = 0, changes = 0;

      snprintf(p, sizeof(p), "%s/clean.txt", w);
      int started = 0;

      for (int i = 0; i < THREADS; i++) {
        a[i] = (struct stress_arg){.path = p, .scans = SCANS};
        if (pthread_create(&t[i], NULL, stress_thread, &a[i]) != 0) {
          fprintf(stderr, "pthread_create failed for stress thread %d\n", i);
          break;
        }
        started++;
      }
      /* Join only what started, and report what actually ran, so a failed
       * create can neither crash the join nor pass as the full count. */
      for (int i = 0; i < started; i++) {
        pthread_join(t[i], NULL);
        bad += a[i].bad;
        changes += a[i].pid_changes;
      }
      printf("STRESS threads=%d scans=%d bad=%d worker_changes=%d\n", started,
             started * SCANS, bad, changes);
      if (started != THREADS) {
        privsep_stop();
        return 2;
      }
      privsep_stop();
      return 0;
    }
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
  /* Proof the cases above really ran in a worker: read this thread's worker
   * back from /proc while it is still alive. */
  if (privsep_enabled && privsep_w.sock >= 0) {
    char sp[64], line[256];
    FILE *sf;

    snprintf(sp, sizeof(sp), "/proc/%d/status", (int)privsep_w.pid);
    sf = fopen(sp, "r");
    while (sf && fgets(line, sizeof(line), sf))
      if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
          !strncmp(line, "CapEff:", 7) || !strncmp(line, "NoNewPrivs:", 11) ||
          !strncmp(line, "Seccomp:", 8))
        printf("WORKER %s", line);
    if (sf)
      fclose(sf);
  }
  /* And the spawner that made it (Stage 1f): still root, but cut to four
   * capabilities, with NoNewPrivs and its own seccomp filter. */
  if (privsep_enabled) {
    char sp[64], line[256];
    FILE *sf;

    snprintf(sp, sizeof(sp), "/proc/%d/status", (int)privsep_cl.spawner_pid);
    sf = fopen(sp, "r");
    while (sf && fgets(line, sizeof(line), sf))
      if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
          !strncmp(line, "CapPrm:", 7) || !strncmp(line, "CapBnd:", 7) ||
          !strncmp(line, "CapAmb:", 7) || !strncmp(line, "NoNewPrivs:", 11) ||
          !strncmp(line, "Seccomp:", 8))
        printf("SPAWNER %s", line);
    if (sf)
      fclose(sf);
  }
  privsep_stop();
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

# A real-text clean sample (numbers, not the generated word text above).
seq 1 5000 > "$BUILD_DIR/clean-sample.txt"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Output file of the mode being checked; set by the caller of verify().
OUT=""

# Compare each CASE line with its sha= field removed (the digest is checked
# separately below), so the expectation table is independent of the clean
# sample's contents.
actual_case() {
    grep -F "CASE $1 " "$OUT" | sed -E 's/ sha=[0-9a-f]*//'
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

# The expectations are the same for both modes: moving the content analysis
# into a worker must not change a single verdict, rule name, score or
# quarantine outcome (#103).
verify() {
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
    if grep -qx 'CASE rescan_gone open-failed' "$OUT"; then
        pass "convicted file no longer at its original path"
    else
        fail "convicted file no longer at its original path"
    fi
    # Six convictions: yara_override, yara_sum, weak_then_fuzzy, fuzzy_only,
    # tlsh_only, signature - each leaves exactly one file plus one sidecar.
    if grep -qx 'QDIR files=6 metas=6' "$OUT"; then
        pass "6 quarantined files, 6 sidecars"
    else
        fail "6 quarantined files, 6 sidecars ($(grep '^QDIR' "$OUT"))"
    fi
    if grep -qx 'METRICS scans_total=11 scans_malicious=6' "$OUT"; then
        pass "metrics: 11 scans, 6 malicious"
    else
        fail "metrics: 11 scans, 6 malicious ($(grep '^METRICS' "$OUT"))"
    fi

    echo "digests:"
    local bad_sha want_sha got_sha c
    bad_sha="$(grep '^CASE .* sha=' "$OUT" | sed -E 's/.* sha=([0-9a-f]*) .*/\1/' | grep -vcE '^[0-9a-f]{64}$')"
    if [ "$bad_sha" = "0" ]; then
        pass "every scan reports a 64-hex SHA-256"
    else
        fail "$bad_sha scan(s) reported a missing or malformed SHA-256"
    fi
    want_sha="$(sha256sum "$BUILD_DIR/clean-sample.txt" | cut -d' ' -f1)"
    for c in clean_ondemand clean_kernelhash; do
        got_sha="$(grep -F "CASE $c " "$OUT" | sed -E 's/.* sha=([0-9a-f]*) .*/\1/')"
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
        END { exit bad ? 1 : 0 }' "$OUT"; then
        pass "every QUARANTINED line is preceded by its match line"
    else
        fail "a QUARANTINED line appeared without a preceding match line"
    fi
}

# run_mode <name> [VAR=value ...]: a fresh work dir per mode, since each run
# quarantines the files it convicts.
run_mode() {
    local name="$1"
    shift
    local work="$BUILD_DIR/work-$name"
    mkdir -p "$work"
    if ! env "$@" "$BUILD_DIR/harness" "$work" "$BUILD_DIR/clean-sample.txt" \
            > "$BUILD_DIR/out-$name.txt" 2> "$BUILD_DIR/err-$name.txt"; then
        echo "FAIL: harness ($name) exited non-zero:"
        cat "$BUILD_DIR/err-$name.txt"
        exit 1
    fi
    OUT="$BUILD_DIR/out-$name.txt"
}

echo "== in-process analysis =="
run_mode inproc
verify

# The worker mode needs root: workers drop to another uid, empty their
# capabilities and install a seccomp filter, and the parent checks all of it
# in /proc before sending a scan. Without root this prints SKIP, never PASS
# (the same convention as the privsep_* tests):
#   sudo tests/test_perform_scan.sh
echo
echo "== analysis in unprivileged workers (AVD_PRIVSEP) =="
if [ "$(id -u)" -ne 0 ]; then
    echo "  SKIP: needs root (workers change uid and install seccomp)"
else
    run_mode privsep HARNESS_PRIVSEP=1
    verify
    echo "worker mode:"
    if grep -q 'privilege separation on' "$OUT"; then
        pass "the scans ran with privilege separation on"
    else
        fail "privilege separation did not start"
    fi
    # The convictions above carry inconclusive=0, so they cannot have come
    # from a failed-open worker; this checks the worker itself.
    if grep -qP '^WORKER Uid:\t65534\t65534\t65534\t65534$' "$OUT" &&
       grep -qP '^WORKER Gid:\t65534\t65534\t65534\t65534$' "$OUT" &&
       grep -qP '^WORKER CapEff:\t0+$' "$OUT" &&
       grep -qP '^WORKER NoNewPrivs:\t1$' "$OUT" &&
       grep -qP '^WORKER Seccomp:\t2$' "$OUT"; then
        pass "the worker ran as the unprivileged user, no capabilities, NoNewPrivs, seccomp filter"
    else
        fail "the worker was not confined as expected ($(grep '^WORKER' "$OUT" | tr '\n\t' '; '))"
    fi
    # The spawner keeps exactly CAP_KILL, CAP_SETGID, CAP_SETUID and
    # CAP_SETPCAP (bits 5-8 = 0x1e0), in every set that matters.
    if grep -qP '^SPAWNER Uid:\t0\t0\t0\t0$' "$OUT" &&
       grep -qP '^SPAWNER CapEff:\t0+1e0$' "$OUT" &&
       grep -qP '^SPAWNER CapPrm:\t0+1e0$' "$OUT" &&
       grep -qP '^SPAWNER CapBnd:\t0+1e0$' "$OUT" &&
       grep -qP '^SPAWNER CapAmb:\t0+$' "$OUT" &&
       grep -qP '^SPAWNER NoNewPrivs:\t1$' "$OUT" &&
       grep -qP '^SPAWNER Seccomp:\t2$' "$OUT"; then
        pass "the spawner kept only SETUID, SETGID, SETPCAP and KILL, with NoNewPrivs and a seccomp filter"
    else
        fail "the spawner was not locked down as expected ($(grep '^SPAWNER' "$OUT" | tr '\n\t' '; '))"
    fi
    if grep -qE 'privsep: .*(failed|no worker)' "$BUILD_DIR/err-privsep.txt"; then
        fail "a worker failed during the run"
        grep -E 'privsep:' "$BUILD_DIR/err-privsep.txt" | head -5
    else
        pass "no worker failure was logged"
    fi

    # Four scan threads, 600 scans each: every scan must be a conclusive
    # clean, and each thread must have replaced its worker twice (after 256
    # and 512 scans), which is the recycle path.
    echo "concurrency and recycling:"
    mkdir -p "$BUILD_DIR/work-stress"
    if env HARNESS_PRIVSEP=1 HARNESS_STRESS=1 "$BUILD_DIR/harness" \
            "$BUILD_DIR/work-stress" "$BUILD_DIR/clean-sample.txt" \
            > "$BUILD_DIR/out-stress.txt" 2> "$BUILD_DIR/err-stress.txt"; then
        if grep -qx 'STRESS threads=4 scans=2400 bad=0 worker_changes=8' "$BUILD_DIR/out-stress.txt"; then
            pass "2400 scans over 4 threads, none failed, 8 worker recycles"
        else
            fail "stress result ($(grep '^STRESS' "$BUILD_DIR/out-stress.txt"))"
        fi
    else
        fail "stress run exited non-zero"
        head -5 "$BUILD_DIR/err-stress.txt"
    fi

    # Losing the spawner means no worker can ever be replaced. avd must exit
    # non-zero (systemd restarts it) and must not carry on scanning in the
    # root process, so no CASE line may have been produced.
    echo "spawner loss:"
    mkdir -p "$BUILD_DIR/work-spawnerloss"
    env HARNESS_PRIVSEP=1 HARNESS_KILL_SPAWNER=1 "$BUILD_DIR/harness" \
        "$BUILD_DIR/work-spawnerloss" "$BUILD_DIR/clean-sample.txt" \
        > "$BUILD_DIR/out-loss.txt" 2> "$BUILD_DIR/err-loss.txt"
    rc=$?
    if [ "$rc" -eq 1 ] && grep -q 'the spawner is gone' "$BUILD_DIR/err-loss.txt"; then
        pass "avd exits 1 when the spawner is lost"
    else
        fail "avd did not exit 1 on spawner loss (exit $rc)"
    fi
    if grep -q '^CASE ' "$BUILD_DIR/out-loss.txt"; then
        fail "scans carried on after the spawner was lost"
    else
        pass "no scan was done in the root process after the spawner was lost"
    fi

    # A spawner that cannot lock itself down must stop avd at startup, before
    # it reports privilege separation as on, not later when the channel closes.
    # Natural failure injection, no test hook in the binary: start the harness
    # with CAP_SETPCAP gone from the bounding set. The spawner needs it, and
    # the lockdown's first step refuses to run without it. Needs setpriv.
    echo "spawner lockdown failure at startup:"
    if command -v setpriv >/dev/null 2>&1 &&
       setpriv --bounding-set=-setpcap true 2>/dev/null; then
        mkdir -p "$BUILD_DIR/work-lockfail"
        setpriv --bounding-set=-setpcap env HARNESS_PRIVSEP=1 "$BUILD_DIR/harness" \
            "$BUILD_DIR/work-lockfail" "$BUILD_DIR/clean-sample.txt" \
            > "$BUILD_DIR/out-lockfail.txt" 2> "$BUILD_DIR/err-lockfail.txt"
        rc=$?
        # A non-zero exit alone proves nothing: the harness also exits non-zero
        # when its own setup fails (a missing sample, rules or corpora that do
        # not load), before privsep_start() ever runs. Require privsep's own
        # diagnostic, and only the one a lockdown refusal produces: the spawner
        # exits, so the channel closes and avd logs that the spawner is lost.
        # "the spawner did not produce a hardened worker" is NOT accepted: a
        # spawner that skipped its lockdown also gets that, when its first worker
        # fails hardening without CAP_SETPCAP (checked by skipping the lockdown).
        # avd does not log why the spawner died yet (docs, "Open items"), so
        # this is the best discriminator there is, not a proof of the cause.
        diag="$(grep -m1 'avd: privsep: privsep spawner lost' "$BUILD_DIR/err-lockfail.txt")"
        if [ "$rc" -ne 0 ] && [ -n "$diag" ]; then
            pass "avd stops when the spawner cannot lock itself down (exit $rc)"
            echo "        avd said: $diag"
            if grep -q 'privilege separation on' "$BUILD_DIR/out-lockfail.txt"; then
                fail "avd reported privilege separation as on before the spawner was locked down"
            else
                pass "avd never reported privilege separation as on"
            fi
            if grep -q '^CASE ' "$BUILD_DIR/out-lockfail.txt"; then
                fail "scans ran with a spawner that was never locked down"
            else
                pass "no scan ran"
            fi
        else
            fail "avd did not stop for a failed spawner lockdown (exit $rc, no privsep diagnostic): $(head -3 "$BUILD_DIR/err-lockfail.txt" | tr '\n' ' ')"
        fi
    else
        echo "  SKIP: setpriv with --bounding-set is not available"
    fi

    # The harness above calls privsep_start() directly, so it never reaches
    # avd's own AVD_PRIVSEP read or the hyprav-scan account check. Run the
    # real avd for those. Each case runs in a private mount namespace with a
    # bind-mounted copy of /etc/passwd, so the host's accounts are never
    # touched, and checks with getent that the namespace really shows the
    # entry it intends (nscd or another NSS source could bypass the copy)
    # before starting avd; if it does not, the case is skipped, not passed.
    # The refusal comes before avd needs the kernel module.
    echo "startup (AVD_PRIVSEP):"
    AVD_BIN="$BUILD_DIR/avd"
    AVD_START="$BUILD_DIR/avd-start"
    mkdir -p "$AVD_START/rules" "$AVD_START/q"
    chmod 700 "$AVD_START/q"
    # Deliberately no rules, fuzzy or TLSH entries: avd accepts an empty rules
    # directory (it warns that every scan will report clean). The cases that
    # get past the account check start a real avd, and if the kernel module
    # is loaded it registers for scan requests until the timeout, so nothing
    # it sees may be convictable or quarantinable.
    : > "$AVD_START/fuzzy.txt"
    : > "$AVD_START/tlsh.txt"
    # shellcheck disable=SC2086 # $CFLAGS_PC and $LIBS are intentionally word-split
    if ! cc -O2 -w -I"$AVD_DIR" $CFLAGS_PC -o "$AVD_BIN" "$AVD_DIR/avd.c" \
            "$AVD_DIR/sha256.c" "$AVD_DIR/tlsh_core.c" "$AVD_DIR/tlsh_shim.c" \
            $LIBS 2> "$BUILD_DIR/cc-avd.log"; then
        fail "could not build avd for the startup cases"
        cat "$BUILD_DIR/cc-avd.log"
    elif ! command -v unshare >/dev/null 2>&1; then
        echo "  SKIP: unshare is not available"
    elif ! unshare -m --propagation private true >/dev/null 2>&1; then
        # Installed but not allowed (a restricted container): skip, do not fail.
        echo "  SKIP: mount namespaces are not available"
    else
        # startup_case <name> <passwd line, or empty for "no such user"> <want>
        #              [AVD_PRIVSEP value; default 1, empty means unset]
        # want: refuse | proceed | off
        startup_case() {
            local name="$1" line="$2" want="$3" psval="${4-1}"
            local pw="$BUILD_DIR/passwd-$name" log="$BUILD_DIR/start-$name.log" rc
            local shown="set to $psval"
            [ -n "$psval" ] || shown="unset"
            grep -v '^hyprav-scan:' /etc/passwd > "$pw"
            [ -n "$line" ] && echo "$line" >> "$pw"
            # shellcheck disable=SC2016 # expanded by the inner shell, on purpose
            unshare -m --propagation private env PW="$pw" EXPECT="$line" \
                PSVAL="$psval" bash -c '
                if [ -n "$PSVAL" ]; then export AVD_PRIVSEP="$PSVAL"; else unset AVD_PRIVSEP; fi
                mount --bind "$PW" /etc/passwd || exit 77
                [ "$(getent passwd hyprav-scan)" = "$EXPECT" ] || exit 77
                exec timeout 15 "$@"' _ \
                "$AVD_BIN" "$AVD_START/rules" "$AVD_START/fuzzy.txt" \
                "$AVD_START/q" "$AVD_START/tlsh.txt" > "$log" 2>&1
            rc=$?
            if [ "$rc" -eq 77 ]; then
                echo "  SKIP: $name (could not give the namespace the intended hyprav-scan entry)"
                return
            fi
            if [ "$want" = refuse ]; then
                if [ "$rc" -eq 1 ] &&
                   grep -qF 'the unprivileged user "hyprav-scan" is missing or is root' "$log" &&
                   ! grep -q 'privilege separation on' "$log"; then
                    pass "$name: avd exits 1 and names the hyprav-scan user"
                else
                    fail "$name: expected exit 1 and the refusal message (exit $rc)"
                    head -5 "$log"
                fi
            elif [ "$want" = off ]; then
                # Opt-in means off by default: with AVD_PRIVSEP unset avd must
                # not look at the account (here it is missing, which would be a
                # refusal if the default were on), must not start workers, and
                # must get as far as the netlink stage like the cases below
                # (exit 1 at the family lookup, or 124 if the module is loaded).
                if { [ "$rc" -eq 1 ] || [ "$rc" -eq 124 ]; } &&
                   { [ "$rc" -eq 124 ] || grep -q 'av module loaded' "$log"; } &&
                   ! grep -qF 'is missing or is root' "$log" &&
                   ! grep -q 'privilege separation on' "$log"; then
                    pass "$name: with AVD_PRIVSEP $shown avd skips the account check and starts no workers"
                else
                    fail "$name: avd did not behave as default-off (exit $rc)"
                    head -5 "$log"
                fi
            else
                # Past the check: no refusal, and the spawner came up. Without
                # the kernel module avd then stops at the netlink family
                # lookup (exit 1); with it loaded avd runs until the timeout.
                if { [ "$rc" -eq 1 ] || [ "$rc" -eq 124 ]; } &&
                   grep -q 'privilege separation on' "$log" &&
                   ! grep -qF 'is missing or is root' "$log"; then
                    pass "$name: a valid hyprav-scan user is accepted"
                else
                    fail "$name: expected avd to get past the account check (exit $rc)"
                    head -5 "$log"
                fi
            fi
        }
        startup_case user-missing ""                                                        refuse
        startup_case uid-zero     "hyprav-scan:x:0:65534::/:/usr/sbin/nologin"              refuse
        startup_case gid-zero     "hyprav-scan:x:65534:0::/:/usr/sbin/nologin"              refuse
        startup_case user-valid   "hyprav-scan:x:65534:65534::/:/usr/sbin/nologin"          proceed
        startup_case default-off  ""                                                        off     ""
        startup_case privsep-zero ""                                                        off     "0"
    fi
fi

echo
echo "perform_scan: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
