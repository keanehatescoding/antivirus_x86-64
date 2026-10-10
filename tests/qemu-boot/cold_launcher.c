/* SPDX-License-Identifier: MIT */
/* Dedicated regression case for #87: av.ko's old exec hook was a
 * kprobe on __x64_sys_execve/execveat that copied the pathname with
 * strncpy_from_user() in atomic/kprobe context. That can't sleep to
 * fault in a userspace page that isn't resident yet, so a pathname
 * argument on a genuinely cold page made the hook silently skip
 * hashing/killing. The hook now probes security_bprm_check() and
 * pins bprm->file instead (see av/main.c's handler_pre_bprm_check()),
 * so this exec must be detected and killed like any other.
 *
 * This is a SEPARATE, minimal binary rather than another code path in
 * init.c on purpose: the only reliable way to guarantee a pathname
 * argument's backing page is genuinely untouched by *this process* is
 * for it to be the very first thing a freshly execve()'d image
 * references, before anything else in the program has had a chance
 * to touch nearby .rodata. init.c itself can't offer that guarantee
 * once it's already running (mounting filesystems, reading av.ko,
 * printing status, etc. all touch various pages first) - but a tiny
 * program whose entire body is "execve() a literal path, do nothing
 * else first" gets a fresh, untouched address space from the kernel's
 * own ELF loader and immediately exec's before doing anything that
 * would fault this string in as a side effect.
 *
 * Deliberately does NOT touch the pathname first (init.c's primary
 * checks do) - the entire point here is exercising the cold-page case
 * on purpose, so a regression back to a pathname-copying hook shows
 * up as a CI failure.
 */
#include <unistd.h>

int main(void) {
  char *const argv[] = {"/tmp/eicar_cold.com", NULL};

  execve("/tmp/eicar_cold.com", argv, NULL);
  /* Only reached if execve itself failed (expected: eicar_cold.com is
   * plain text, not a valid ELF, so this fails ENOEXEC - but only
   * after security_bprm_check() has already run and queued the scan).
   * The kill is workqueue-deferred (async) and can race against this
   * process's own exit. Same race, same fix as init.c's identical
   * usleep(1000000) after its own failed execv(): without this delay,
   * a working hook could still get misreported as a bypass just
   * because this process exited before the kill arrived. */
  usleep(1000000);
  return 1;
}
