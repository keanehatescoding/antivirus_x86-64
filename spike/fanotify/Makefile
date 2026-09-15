# Spike build - NOT part of the main build. Nothing in the repo's normal
# `make` path reaches here; this is built by hand when investigating the
# exec-interception redesign (#102).
#
# Needs: a C compiler and kernel headers with FAN_OPEN_EXEC_PERM (5.0+).
# `make check` additionally needs root and
# CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y.

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra

# One source, three binaries: distinct inodes AND distinguishable at
# runtime by the marker byte each writes. See target.c.
TARGETS := target_orig target_decoy target_unmarked
BINS    := fanotify_spike $(TARGETS)

.PHONY: all clean check
all: $(BINS)

fanotify_spike: fanotify_spike.c
	$(CC) $(CFLAGS) -o $@ $<

target_orig: target.c
	$(CC) $(CFLAGS) -DMARKER_CHAR="'A'" -o $@ $<

target_decoy: target.c
	$(CC) $(CFLAGS) -DMARKER_CHAR="'B'" -o $@ $<

target_unmarked: target.c
	$(CC) $(CFLAGS) -DMARKER_CHAR="'U'" -o $@ $<

# Needs root (FAN_CLASS_CONTENT wants CAP_SYS_ADMIN). Safe on a live
# machine: marks are per-inode on throwaway copies, never FAN_MARK_MOUNT.
check: all
	./run_spike.sh

clean:
	rm -f $(BINS)
