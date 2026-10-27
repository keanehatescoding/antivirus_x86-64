# tests/fuzz/Makefile - libFuzzer targets for avd's externally reachable
# parsers (#105). Needs clang with the libFuzzer and sanitizer runtimes
# (Debian/Ubuntu: clang libclang-rt-dev; Arch: clang compiler-rt).
#
#   make -C tests/fuzz            # build every target
#   make -C tests/fuzz replay     # run each target once over its seed corpus
#                                 # (regression check, finishes in seconds)
#   make -C tests/fuzz run SECS=60  # fuzz each target for 60 seconds
#
# Corpora live in corpus/<target>/ and are checked in: seeds the fuzzer
# mutates from, plus any minimized crasher it ever found (keep those - they
# are the regression tests). New coverage found while fuzzing goes to
# work/<target>/, which is not tracked.
#
# fuzz_control_line includes userspace/avd/avd.c itself, so it needs the
# same libraries avd does (libnl-genl-3, yara, libfuzzer-compatible link).

CLANG   ?= clang
PKG_CONFIG ?= pkg-config
SECS    ?= 30

SAN     := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
CFLAGS  ?= -g -O1 -fno-omit-frame-pointer
AVD_DIR := ../../userspace/avd

PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0 yara 2>/dev/null)
PC_LIBS   := $(shell $(PKG_CONFIG) --libs libnl-genl-3.0 yara 2>/dev/null) \
             $(shell $(PKG_CONFIG) --libs fuzzy 2>/dev/null || echo -lfuzzy) -lpthread

HEADER_TARGETS := fuzz_fan_parse fuzz_control_parse
AVD_TARGETS    := fuzz_control_line
TARGETS        := $(HEADER_TARGETS) $(AVD_TARGETS)

all: $(TARGETS)

$(HEADER_TARGETS): %: %.c $(AVD_DIR)/control_parse.h $(AVD_DIR)/fan_parse.h
	$(CLANG) $(CFLAGS) $(SAN) -I$(AVD_DIR) -o $@ $<

$(AVD_TARGETS): %: %.c $(AVD_DIR)/avd.c $(AVD_DIR)/sha256.c \
                $(AVD_DIR)/tlsh_core.c $(AVD_DIR)/tlsh_shim.c \
                $(AVD_DIR)/control_parse.h $(AVD_DIR)/fan_parse.h
	$(CLANG) $(CFLAGS) $(SAN) -w -I$(AVD_DIR) $(PC_CFLAGS) -o $@ $< \
	    $(AVD_DIR)/sha256.c $(AVD_DIR)/tlsh_core.c $(AVD_DIR)/tlsh_shim.c \
	    $(PC_LIBS)

replay: all
	@set -e; for t in $(TARGETS); do \
	    echo "== replay $$t"; \
	    ./$$t -runs=0 corpus/$$t; \
	done

run: all
	@set -e; for t in $(TARGETS); do \
	    mkdir -p work/$$t; \
	    echo "== fuzz $$t for $(SECS)s"; \
	    ./$$t -max_total_time=$(SECS) -print_final_stats=1 \
	        work/$$t corpus/$$t; \
	done

# Binaries only: work/ (new coverage) and crash-* reproducers from an
# earlier `make run` are results, not build products. test_fuzz_replay.sh
# uses this target so a replay never deletes them.
clean-bin:
	rm -f $(TARGETS)

clean: clean-bin
	rm -rf work crash-* leak-* timeout-* oom-*

.PHONY: all replay run clean clean-bin
