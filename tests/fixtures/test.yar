// SPDX-License-Identifier: MIT
/*
 * test.yar - TEST FIXTURE ONLY, never installed to production (see
 * userspace/avd/Makefile's explicit production rule list and
 * packaging/arch/PKGBUILD's backup=() array, neither of which
 * references this file). It lives under tests/fixtures/ rather than
 * rules/ precisely so the install globs can never pick it up: its
 * Suspicious_Shell_Reverse_Shell_String rule (weight=100,
 * override=true on the literal string "/bin/sh -i") would otherwise
 * quarantine legitimate scripts on every fresh install (issue #86).
 *
 * A minimal rule set for testing the YARA integration itself.
 *
 * This deliberately does NOT duplicate the SHA-256 EICAR signature
 * already in av/main.c - the point is to prove the YARA path works
 * independently (string/pattern matching, not hash lookup). Real
 * malware rule sets go in this directory too (e.g. pulled from
 * community rule repositories) once you're testing against actual
 * samples rather than just the plumbing.
 *
 * v1.0.0-merge: added weight + override meta. Without these, the
 * v0.9.1 weighted-scoring system (see heuristics.yar) means these
 * rules would each contribute 0 to the aggregate score and NEVER
 * independently convict - silently breaking the documented v0.3.0
 * README walkthrough, which specifically instructs removing the
 * kernel-side EICAR signature to force the file through YARA alone.
 * These are explicit, deterministic test fixtures, not probabilistic
 * heuristics - override = true is appropriate here in a way it
 * usually isn't (compare to the careful, selective override tier in
 * elf_analysis.yar).
 */

rule EICAR_Test_String
{
    meta:
        description = "Detects the standard EICAR antivirus test string"
        author = "kernel-av project"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        weight = 100
        override = true

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

rule Suspicious_Shell_Reverse_Shell_String
{
    meta:
        description = "Flags a common /bin/sh -i reverse shell pattern - test rule, not a real detector"
        author = "kernel-av project"
        weight = 100
        override = true

    strings:
        $pattern = "/bin/sh -i"

    condition:
        $pattern
}
