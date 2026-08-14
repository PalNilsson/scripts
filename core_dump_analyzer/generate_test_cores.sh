#!/usr/bin/env bash
#
# Generate two reproducible core dumps for validating analyze_core_dump.py
# without needing a real ATLAS core:
#
#   core.crash.NNNN  A multi-threaded C program that dereferences a NULL pointer.
#                    Exercises crash mode: fault signal, faulting frame, idle
#                    worker threads that must be grouped and marked idle.
#
#   core.hang.NNNN   A multi-threaded Python program stuck in an unbounded loop,
#                    snapshotted with gcore. Exercises hang mode: no fault signal,
#                    one busy thread among idle ones, and py-bt Python frames.
#
# Usage:  bash tests/generate_test_cores.sh [output_dir]
#
# Requires: gcc, gdb, python3. For py-bt coverage also install the interpreter's
# gdb helper (python3-debuginfo on RHEL, python3-dbg on Debian/Ubuntu).

set -euo pipefail

OUT_DIR="${1:-$(pwd)/tests/artifacts}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

for tool in gcc gdb python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 1; }
done

echo "==> Building the crashing test program"
cat > crasher.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

typedef struct { int event_id; char name[32]; double *payload; } Hit;

static void *idle_worker(void *arg) { (void)arg; for (;;) sleep(60); return NULL; }

static double reconstruct_cluster(Hit *h, int n) {
    double total = 0.0;
    for (int i = 0; i < n; i++) total += h->payload[i];   /* payload is NULL */
    return total;
}

static double process_event(Hit *h) { return reconstruct_cluster(h, 10); }

int main(void) {
    pthread_t t[6];
    for (int i = 0; i < 6; i++) pthread_create(&t[i], NULL, idle_worker, NULL);
    sleep(1);
    Hit *h = calloc(1, sizeof(Hit));
    h->event_id = 40771;
    strcpy(h->name, "EMB1_cluster");
    h->payload = NULL;
    printf("%f\n", process_event(h));
    return 0;
}
CEOF
gcc -g -O0 -pthread -o crasher crasher.c

echo "==> Producing a crash core"
ulimit -c unlimited
rm -f core core.crash.*
(./crasher || true) >/dev/null 2>&1
CRASH_CORE=$(ls -t core core.* 2>/dev/null | head -1 || true)
if [ -n "$CRASH_CORE" ] && [ -f "$CRASH_CORE" ]; then
    mv "$CRASH_CORE" core.crash.1234
    echo "    wrote $OUT_DIR/core.crash.1234"
else
    echo "    WARNING: no core produced. Check /proc/sys/kernel/core_pattern;" >&2
    echo "    a pipe handler such as systemd-coredump or apport intercepts cores." >&2
fi

echo "==> Building the looping test program"
cat > looper.py <<'PYEOF'
"""A deliberately non-terminating job, used to produce a hang-mode core."""
import threading
import time


def idle_worker() -> None:
    """Sleep forever, standing in for an idle worker thread."""
    while True:
        time.sleep(60)


def merge_overlapping_hits(hits: list[int]) -> None:
    """Grow the list forever: the index never advances past a multiple of seven."""
    i = 0
    while i < len(hits):
        if hits[i] % 7 == 0:
            hits.append(hits[i] + 1)
        i += 0 if hits[i] % 7 == 0 else 1


def process_event(event_id: int) -> None:
    """Entry point mimicking per-event reconstruction."""
    merge_overlapping_hits([event_id, 7, 14])


for _ in range(4):
    threading.Thread(target=idle_worker, daemon=True).start()
process_event(40771)
PYEOF

echo "==> Producing a hang core with gcore"
rm -f core.hang.*
python3 looper.py >/dev/null 2>&1 &
LOOP_PID=$!
sleep 4
gdb -q -batch -p "$LOOP_PID" -ex "generate-core-file core.hang.5678" 2>&1 | tail -1
kill -9 "$LOOP_PID" 2>/dev/null || true
wait "$LOOP_PID" 2>/dev/null || true
[ -f core.hang.5678 ] && echo "    wrote $OUT_DIR/core.hang.5678"

echo
echo "Done. Try:"
echo "  python analyze_core_dump.py $OUT_DIR/core.crash.1234 --no-llm"
echo "  python analyze_core_dump.py $OUT_DIR/core.hang.5678  --no-llm"
