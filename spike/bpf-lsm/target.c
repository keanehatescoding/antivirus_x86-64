// SPDX-License-Identifier: GPL-2.0
/* Exec target for enforce_test.c. Copied to two paths so the two copies
 * have distinct inodes: one is added to blocked_files, the other is not.
 * Exits 7 so the parent can tell "ran" from "execv failed with errno". */
int main(void)
{
	return 7;
}
