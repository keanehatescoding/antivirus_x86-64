/*
 * heuristics.yar - v0.4.0: string & API heuristics.
 * v0.9.1: added numeric `weight` meta (see below).
 *
 * Uses YARA's built-in `elf` module to inspect the DYNAMIC SYMBOL TABLE
 * (imported functions) directly, rather than doing raw string matching -
 * this is more precise than a plain string search, since it only fires
 * on genuine imports rather than the function name appearing anywhere
 * in the file (e.g. in a string literal, a comment compiled into debug
 * info, etc.).
 *
 * IMPORTANT CAVEAT FOR YOUR REPORT: every API here has entirely
 * legitimate uses (debuggers legitimately use ptrace, package managers
 * legitimately use memfd_create, etc.) - these rules are individually
 * HIGH FALSE-POSITIVE, LOW CONFIDENCE. Real heuristic engines combine
 * signals (multiple suspicious imports together, absence of expected
 * "normal" imports, combined with behavioral/entropy signals from later
 * milestones) rather than alerting on any single import. The
 * Multiple_Suspicious_Imports rule below is a deliberately crude
 * first attempt at that combination - discuss its false-positive rate
 * honestly in your report rather than presenting single-API matches as
 * strong detections.
 *
 * WEIGHT META: avd.c no longer convicts on any single rule match - it
 * sums the `weight` meta of every matching rule and only sends
 * AV_VERDICT_MALICIOUS once the total crosses MALICIOUS_SCORE_THRESHOLD
 * (100, see avd.c). This was added after real testing killed /usr/bin/zsh,
 * /bin/sh, and /usr/bin/uwsm - all legitimate system binaries that
 * happened to import one flagged API each. The weights below are a
 * direct numeric translation of the `confidence` strings already in
 * each rule; keep the two in sync if you tune one.
 *
 * DOUBLE-COUNTING NOTE (#131): Imports_Ptrace and Imports_Memfd_Create
 * are `private` so they never contribute to that sum directly - only
 * Multiple_Suspicious_Imports' combined weight counts when both fire.
 * Without `private`, a sample matching both would score 15 + 15 + 40 =
 * 70 instead of the intended 40, inflating it toward the threshold on
 * top of any structural-rule corroboration. Imports_Dlopen and
 * Imports_Mprotect stay public on purpose: neither is referenced by
 * the combo rule, so there is nothing to double-count for them, and
 * their standalone weights remain visible in avd's score/log output.
 */
import "elf"

private rule Imports_Ptrace
{
    meta:
        description = "Imports ptrace() - used legitimately by debuggers, but also for anti-debugging tricks and process injection"
        confidence = "low"
        weight = 15
    condition:
        for any sym in elf.dynsym : (sym.name == "ptrace")
}

private rule Imports_Memfd_Create
{
    meta:
        description = "Imports memfd_create() - creates an anonymous, RAM-only file; used legitimately (e.g. systemd, some package managers) but also for fileless execution (loading and exec'ing a payload that never touches disk)"
        confidence = "low"
        weight = 15
    condition:
        for any sym in elf.dynsym : (sym.name == "memfd_create")
}

rule Imports_Dlopen
{
    meta:
        description = "Imports dlopen() - standard dynamic loading, extremely common in legitimate software; included here mainly as a building block for compound rules below, not meaningful alone"
        confidence = "very low - do not alert on this alone, dlopen is ubiquitous"
        weight = 5
    condition:
        for any sym in elf.dynsym : (sym.name == "dlopen")
}

rule Imports_Mprotect
{
    meta:
        description = "Imports mprotect() - used to change memory page permissions; legitimate for JIT compilers and language runtimes, but also the standard way to mark a memory region executable after writing shellcode into it"
        confidence = "very low alone - JIT-based software (browsers, many language runtimes) does this routinely"
        weight = 10
    condition:
        for any sym in elf.dynsym : (sym.name == "mprotect")
}

rule Multiple_Suspicious_Imports
{
    meta:
        description = "Imports ptrace AND memfd_create together - a narrower, still crude, attempt at combining weak signals. Individually common; together, a somewhat less common combination worth a second look rather than an automatic verdict"
        confidence = "medium - still expect false positives from legitimate system tooling"
        weight = 40
    condition:
        Imports_Ptrace and Imports_Memfd_Create
}
