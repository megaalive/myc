#!/usr/bin/env bash
# =====================================================================
# _audit018.sh -- MYC-AUDIT-018: test portabel (Windows git-bash + POSIX).
#
# Menutup celah audit: test lama dominan .bat (Windows) dan tidak menguji
# concurrency/deadlock/OOM. Runner ini membangun + menjalankan unit test C
# portabel:
#   1. proc_flood    -- deadlock stdin/stdout, flood 100MiB prefix+tail,
#                      env override (MYC-AUDIT-002/017 + bounded capture).
#   2. oom_guards    -- guard overflow arena + validasi input ekstrem.
#   3. oom_alloc     -- injeksi kegagalan malloc/calloc/realloc (--wrap).
#   4. stress_threads-- concurrency myc_run paralel (Fase 5, juga Windows).
#
# Dijalankan dari _regress_run.bat (bila bash tersedia) atau langsung di
# POSIX/CI Linux. CWD harus root proyek.
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

SRCS="myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c negative.c"
CC="${CC:-gcc}"
FAIL=0

rm -f test/proc_flood test/proc_flood.exe test/oom_guards test/oom_guards.exe \
      test/oom_alloc test/oom_alloc.exe test/stress_threads test/stress_threads.exe

run_built() {
    local name="$1"; shift
    if "$@"; then
        echo "[OK] $name"
    else
        echo "[FAIL] $name"
        FAIL=1
    fi
}

# --- 1. proc_flood: deadlock + flood + env override ---
if $CC -O2 -std=c11 -Wall -Wextra -I. -o test/proc_flood test/proc_flood.c proc.c 2>/dev/null; then
    run_built "audit018 proc_flood (deadlock/flood/env)" test/proc_flood
else
    echo "[FAIL] audit018 proc_flood gagal dibangun"
    FAIL=1
fi

# --- 2. oom_guards: guard overflow arena + input ekstrem ---
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/oom_guards \
       test/oom_guards.c $SRCS 2>/dev/null; then
    run_built "audit018 oom_guards (arena overflow/input)" test/oom_guards
else
    echo "[FAIL] audit018 oom_guards gagal dibangun"
    FAIL=1
fi

# --- 3. oom_alloc: injeksi kegagalan alokasi (butuh GNU ld --wrap) ---
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
       -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
       -o test/oom_alloc test/oom_alloc.c $SRCS 2>/dev/null; then
    run_built "audit018 oom_alloc (OOM injection)" test/oom_alloc
else
    echo "[FAIL] audit018 oom_alloc gagal dibangun (butuh GNU ld --wrap)"
    FAIL=1
fi

# --- 4. stress_threads: concurrency (juga dijalankan _regress_run.bat) ---
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/stress_threads \
       test/stress_threads.c $SRCS 2>/dev/null; then
    run_built "audit018 stress_threads (concurrency)" test/stress_threads
else
    echo "[FAIL] audit018 stress_threads gagal dibangun"
    FAIL=1
fi

rm -f test/proc_flood test/proc_flood.exe test/oom_guards test/oom_guards.exe \
      test/oom_alloc test/oom_alloc.exe test/stress_threads test/stress_threads.exe

echo "audit018: $([ $FAIL -eq 0 ] && echo SELESAI OK || echo GAGAL)"
exit $FAIL
