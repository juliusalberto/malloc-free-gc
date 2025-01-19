CC=gcc
CFLAGS = -fPIC -Wall -Werror=implicit-function-declaration
LIBFLAGS = -shared
ODIR = ./out
TESTFLAGS = -L${ODIR}
MALLOC = mymalloc

ifdef RELEASE
CFLAGS += -O3
else
CFLAGS += -g -ggdb3 -fsanitize=address,undefined
endif

ifdef LOG
CFLAGS += -DENABLE_LOG
endif

ifeq ($(shell uname -s),Darwin)
DYLIB_EXT = dylib
else
DYLIB_EXT = so
endif

ALL_TESTS_SRC=$(wildcard tests/*.c)
ALL_TESTS=$(ALL_TESTS_SRC:%.c=%)
MALLOC_OBJ=$(MALLOC:%=src/%.o)

INTERNAL_TEST_SRCS=$(shell find internal-tests -name '*.c')
INTERNAL_TESTS=$(INTERNAL_TEST_SRCS:%.c=%)

all: $(MALLOC) mygc

# ===================== Build mymalloc as a shared library =====================

$(MALLOC): $(MALLOC_OBJ) | $(ODIR)/
	"$(CC)" $(CFLAGS) $(LIBFLAGS) -o $(ODIR)/lib$(MALLOC).$(DYLIB_EXT) $<

$(MALLOC_OBJ): %  : src/$(MALLOC).c
	"$(CC)" $(CFLAGS) -c -o $@ $<

# ============================================================================
# [ NEW ] Build a separate "mygc" library from mygc.c
# ============================================================================
MYGC = mygc
MYGC_OBJ = $(MYGC:%=src/%.o)

mygc: $(MYGC_OBJ) | $(ODIR)/
	"$(CC)" $(CFLAGS) $(LIBFLAGS) -o $(ODIR)/lib$(MYGC).$(DYLIB_EXT) $(MYGC_OBJ)

$(MYGC_OBJ): % : src/$(MYGC).c
	"$(CC)" $(CFLAGS) -c -o $@ $<

# ======== Build Test files using library specified in MALLOC variable =========

test: $(ALL_TESTS)

$(ALL_TESTS): tests/%: tests/%.o | $(MALLOC)
	"$(CC)" $(CFLAGS) $(TESTFLAGS) $< -l$(MALLOC) -o $@ -Wl,-rpath,"`pwd`"/$(ODIR)

tests/%.o: tests/%.c
	"$(CC)" $(CFLAGS) -c -o $@ $<

# ============================ Build Internal Tests ============================

internal: $(INTERNAL_TESTS)

$(INTERNAL_TESTS): internal-tests/% : internal-tests/%.o | $(MALLOC)
	"$(CC)" $(CFLAGS) $(TESTFLAGS) $^ -l$(MALLOC) -o $@ -Wl,-rpath,"`pwd`"/$(ODIR)

internal-tests/%.o : internal-tests/%.c
	"$(CC)" $(CFLAGS) -c -o $@ $<

# ============================== Build benchmark ===============================

bench: bench/benchmark

bench/benchmark : bench/benchmark.o | $(MALLOC)
	"$(CC)" $(CFLAGS) $(TESTFLAGS) $^ -l$(MALLOC) -o $@ -Wl,-rpath,"`pwd`"/$(ODIR)

bench/benchmark.o : bench/benchmark.c
	"$(CC)" $(CFLAGS) -c -o $@ $<

$(ODIR)/:
	mkdir -p $(ODIR)

# ============================================================================
# [ NEW ] Example: Build a special test ("mygctest") that needs both libraries
# ============================================================================
mygctest: mygctest.o | $(MALLOC) mygc
	"$(CC)" $(CFLAGS) $(TESTFLAGS) $< -l$(MYGC) -l$(MALLOC) -o $@ -Wl,-rpath,"`pwd`"/$(ODIR)

tests/mygctest.o: mygctest.c
	"$(CC)" $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf ./out ./tests/*.dSYM src/*.o tests/*.o internal-tests/*.o bench/*.o bench/benchmark >/dev/null 2>&1 || true
	@for test in $(ALL_TESTS); do \
		rm -rf $$test; \
	done
	@for test in $(INTERNAL_TESTS); do \
		rm -rf $$test; \
	done
