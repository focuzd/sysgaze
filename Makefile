CC ?= cc

CPPFLAGS := -D_GNU_SOURCE -Iinclude
CFLAGS := -std=c23 -O2 -g -Wall -Wextra -Wpedantic -Werror \
	-Wconversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
	-Wformat=2 -Wundef -Wwrite-strings
LDFLAGS :=
LDLIBS :=
comma := ,

PROGRAM := build/sysgaze
TEST_PROGRAM := build/tests/stage1_tests
NDJSON_VALIDATOR := build/tests/ndjson_validator
BENCH_HARNESS := build/bench/harness
BENCH_WORKLOAD := build/bench/workload

CORE_SOURCES := src/buffer.c src/cli.c src/decoder.c src/filter.c src/output.c \
	src/stats.c src/syscall_catalog.c src/tracee_table.c
TRACE_SOURCES := src/trace.c
PROGRAM_SOURCES := src/main.c $(CORE_SOURCES) $(TRACE_SOURCES)
TEST_SOURCES := tests/stage1_tests.c tests/interface_compile.c $(CORE_SOURCES)

FIXTURE_SOURCES := tests/fixtures/exit_fixture.c tests/fixtures/signal_fixture.c \
	tests/fixtures/restart_fixture.c tests/fixtures/decode_fixture.c \
	tests/fixtures/follow_fixture.c tests/fixtures/attach_fixture.c \
	tests/fixtures/signal_state_fixture.c \
	tests/fixtures/interleave_fixture.c tests/fixtures/fault_fixture.c

FIXTURE_SOURCES += tests/fixtures/summary_fixture.c
FIXTURES := $(FIXTURE_SOURCES:tests/fixtures/%.c=build/tests/fixtures/%)

PROGRAM_OBJECTS := $(PROGRAM_SOURCES:%.c=build/obj/%.o)
TEST_OBJECTS := $(TEST_SOURCES:%.c=build/obj/%.test.o)

.PHONY: all test check bench bench-compare bench-smoke update-syscalls clean

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM_OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_PROGRAM): $(TEST_OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(NDJSON_VALIDATOR): tests/ndjson_validator.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(BENCH_HARNESS): benchmarks/harness.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(BENCH_WORKLOAD): benchmarks/workload.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -pthread -o $@

build/obj/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build/obj/%.test.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build/tests/fixtures/%: tests/fixtures/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

build/tests/fixtures/follow_fixture build/tests/fixtures/attach_fixture \
build/tests/fixtures/interleave_fixture: \
	CFLAGS += -pthread

# This fixture must deliver a real SIGSEGV to the tracer; ASan would intercept
# its deliberate PROT_NONE read before ptrace can observe the native fault.
build/tests/fixtures/fault_fixture: tests/fixtures/fault_fixture.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) \
		$(filter-out -fsanitize=address$(comma)undefined,$(CFLAGS)) $< -o $@

# Exact syscall-count assertions must not include sanitizer runtime syscalls.
build/tests/fixtures/summary_fixture: tests/fixtures/summary_fixture.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) \
		$(filter-out -fsanitize=address$(comma)undefined,$(CFLAGS)) $< -o $@

test: $(TEST_PROGRAM) $(NDJSON_VALIDATOR) $(PROGRAM) $(FIXTURES)
	./$(TEST_PROGRAM)
	./tests/cli_integration.sh ./$(PROGRAM)
	./tests/trace_integration.sh ./$(PROGRAM) build/tests/fixtures \
		./$(NDJSON_VALIDATOR)

check: clean
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) \
		CFLAGS="$(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
		LDFLAGS="-fsanitize=address,undefined" test

bench: $(PROGRAM) $(BENCH_HARNESS) $(BENCH_WORKLOAD)
	./$(BENCH_HARNESS) ./$(PROGRAM) ./$(BENCH_WORKLOAD)

bench-compare: $(PROGRAM) $(BENCH_HARNESS) $(BENCH_WORKLOAD)
	@command -v strace >/dev/null || { echo "strace is not installed" >&2; exit 1; }
	./$(BENCH_HARNESS) ./$(PROGRAM) ./$(BENCH_WORKLOAD) "$$(command -v strace)"

bench-smoke: $(PROGRAM) $(BENCH_HARNESS) $(BENCH_WORKLOAD)
	SYSGAZE_BENCH_WARMUPS=1 SYSGAZE_BENCH_ITERATIONS=1 \
		./$(BENCH_HARNESS) ./$(PROGRAM) ./$(BENCH_WORKLOAD) >/dev/null

update-syscalls:
	./tools/update-syscall-names.sh
	./tools/update-syscall-arities.sh

clean:
	rm -rf build

-include $(PROGRAM_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
