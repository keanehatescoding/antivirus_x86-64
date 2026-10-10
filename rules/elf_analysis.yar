// SPDX-License-Identifier: MIT
/*
 * elf_analysis.yar - v0.5.0: ELF header & section analysis.
 * v0.9.1: added numeric `weight` meta - see heuristics.yar for the
 * scoring model. Entry_Point_Outside_Text's weight was set LOWER than
 * its "medium-high" confidence string alone would suggest, after real
 * testing showed it firing on /usr/bin/uwsm (a legitimate systemd
 * session manager) with no packing involved - see the note on that
 * rule below.
 *
 * v1.0.0-merge: added `override = true` to No_Section_Headers and
 * Executable_Stack - these convict on their own regardless of
 * aggregate score, unlike everything else which is purely additive.
 * Why these two specifically: both are verified against real positive
 * AND negative samples (real UPX-packed binary / real -z execstack
 * binary vs. /bin/ls), and structurally there's essentially no
 * legitimate reason a normal binary has zero section headers or an
 * executable stack. This was added after discovering that the
 * additive-only scoring model let the v0.9.0 entropy-dilution evasion
 * finding through the WHOLE pipeline (85/100, below threshold) where
 * it previously only evaded the entropy layer specifically - see
 * docs/evasion-findings.md for the full writeup. Entry_Point_Outside_
 * Text and Has_RWX_Segment deliberately do NOT get override: the
 * former has a confirmed real false positive (uwsm); the latter is
 * now verified against a real RWX sample (see its own confidence
 * meta below) but wasn't re-evaluated for override status as part of
 * that verification pass - it stays purely additive at weight 40
 * until that's deliberately reconsidered, not by default.
 *
 * Every rule here was verified against a REAL packed binary (UPX 4.2.2,
 * packing a small test executable) as well as normal system binaries
 * (/bin/ls) to confirm no false positives - not just checked for valid
 * YARA syntax. See the testing section in the top-level README for the
 * exact commands to reproduce this.
 *
 * CONFIDENCE NOTE FOR YOUR REPORT: unlike the ptrace/memfd_create
 * import checks in heuristics.yar, these structural checks are
 * generally HIGHER confidence - a legitimately compiled binary rarely
 * has zero section headers or an executable stack by accident. They're
 * still not proof of malice (some legitimate packers/protectors exist,
 * and old toolchains occasionally produce executable stacks), but
 * false positives should be rarer than the import-based heuristics.
 * UPDATE: Entry_Point_Outside_Text's real-world false positive on
 * uwsm shows even a "verified against a real sample" structural rule
 * isn't automatically safe to convict on alone - hence why override
 * status is decided per-rule, not applied to the whole file.
 */

import "elf"

rule No_Section_Headers
{
    meta:
        description = "No section headers present - legitimate compilers always emit them; packers (UPX and similar) commonly strip them since only program headers are needed at load time"
        confidence = "medium-high - verified against a real UPX-packed binary"
        weight = 55
        override = true
    condition:
        elf.number_of_sections == 0
}

rule Executable_Stack
{
    meta:
        description = "GNU_STACK segment marked executable - the stack should never be executable on a modern system; either a very old/misconfigured toolchain (gcc -z execstack) or a deliberately weakened binary"
        confidence = "medium-high - verified against a binary built with -z execstack"
        weight = 55
        override = true
    condition:
        for any i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_GNU_STACK and
            elf.segments[i].flags & elf.PF_X
        )
}

rule Has_RWX_Segment
{
    meta:
        description = "A loadable (PT_LOAD) segment is both writable and executable - violates W^X; legitimate binaries essentially never need this, self-modifying/decrypting code does"
        confidence = "medium-high - verified against a real RWX PT_LOAD segment (a -nostdlib freestanding binary linked with `ld -N`/--omagic, which GNU ld itself warns produces an RWX LOAD segment); no false positives across /bin/ls, /bin/bash, /usr/bin/gcc, /usr/bin/python3, or a build without -Wl,-N/--omagic of the same test program - see the README's ELF structural analysis testing section for the exact repro"
        weight = 40
    condition:
        for any i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_LOAD and
            elf.segments[i].flags & elf.PF_W and
            elf.segments[i].flags & elf.PF_X
        )
}

rule Entry_Point_Outside_Text
{
    meta:
        description = "Entry point does not fall within a .text section (or no .text section exists at all) - common in packed/self-decrypting binaries where execution starts in a small stub before jumping to unpacked code elsewhere"
        confidence = "medium-high in the UPX case tested, but confirmed to false-positive on at least one legitimate binary (uwsm) in real testing - see the v0.9.1 note at the top of this file. Treated as a weaker, more corroborating-only signal than its original confidence string suggests."
        weight = 30
    condition:
        not (
            for any i in (0..elf.number_of_sections - 1) : (
                elf.sections[i].name == ".text" and
                elf.entry_point >= elf.sections[i].address and
                elf.entry_point < elf.sections[i].address + elf.sections[i].size
            )
        )
}
