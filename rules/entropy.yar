// SPDX-License-Identifier: MIT
/*
 * entropy.yar - v0.6.0: entropy analysis (packed/encrypted file detection).
 * v0.9.1: added numeric `weight` meta - see heuristics.yar for the
 * scoring model. Note that on the UPX-packed test binary these rules
 * were calibrated against, High_Overall_Entropy fires ALONGSIDE
 * elf_analysis.yar's No_Section_Headers and Entry_Point_Outside_Text
 * (same underlying packing, different angles) - the combined weight of
 * that corroboration is what clears MALICIOUS_SCORE_THRESHOLD, not any
 * single rule here alone.
 *
 * Threshold calibration (measured with a plain Shannon entropy
 * calculation in Python, cross-checked against YARA's math.entropy()):
 *   /bin/ls (normal binary)          ~5.9 bits/byte
 *   a small, mostly-zero test binary ~1.5 bits/byte
 *   the same binary UPX-packed       ~7.3 bits/byte
 *   /dev/urandom (max entropy)       ~8.0 bits/byte
 *
 * 7.0 sits comfortably above normal compiled code and comfortably below
 * pure random/compressed data, giving margin on both sides. Verified
 * against all four real samples above before picking this number - see
 * the README testing section for exact reproduction steps.
 *
 * Two complementary checks, not redundant:
 *   - High_Overall_Entropy: works even when a packer strips section
 *     headers entirely (like UPX's default mode - see elf_analysis.yar's
 *     No_Section_Headers, which catches the same UPX sample from a
 *     different angle)
 *   - High_Entropy_Section: catches packers/protectors that DO keep
 *     section headers but hide compressed/encrypted payload in one
 *     section - verified with a real injected high-entropy section
 *     (via objcopy), since no packer on hand naturally produces this
 *     shape
 */

import "math"
import "elf"

rule High_Overall_Entropy
{
    meta:
        description = "Whole-file Shannon entropy is unusually high - suggests compressed or encrypted content rather than normal compiled code"
        confidence = "medium - verified: fires on a real UPX-packed binary and on random data, stays silent on normal binaries"
        weight = 55
    condition:
        math.entropy(0, filesize) >= 7.0
}

rule High_Entropy_Section
{
    meta:
        description = "A section's content is unusually high entropy relative to typical compiled code - possible packed/encrypted payload hidden in an otherwise normal-looking section table"
        confidence = "medium - verified with a synthetically injected high-entropy section (objcopy); no naturally-occurring sample on hand that preserves sections while packing"
        weight = 45
    condition:
        elf.number_of_sections > 0 and
        for any i in (0..elf.number_of_sections - 1) : (
            elf.sections[i].size > 64 and
            math.entropy(elf.sections[i].offset, elf.sections[i].size) >= 7.0
        )
}
