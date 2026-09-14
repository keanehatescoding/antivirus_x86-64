// SPDX-License-Identifier: GPL-2.0
/* Exec target for enforce_test.c. Copied to two paths so the two copies
 * have distinct inodes: one is added to blocked_files, the other is not.
 *
 * Exits with a known non-zero status so the parent can tell "the target
 * ran to completion" from "the child died some other way". Whether the
 * exec was ALLOWED is reported separately, over a pipe - see try_exec()
 * - so this value carries no errno meaning and need only stay in sync
 * with TARGET_OK in enforce_test.c. */
int main(void)
{
	return 7; /* TARGET_OK */
}
