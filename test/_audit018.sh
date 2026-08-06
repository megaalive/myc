#!/usr/bin/env bash
# =====================================================================
# _audit018.sh -- MYC-AUDIT-018: test portabel (Windows git-bash + POSIX).
#
# Menutup celah audit: test lama dominan .bat (Windows) dan tidak menguji
# concurrency/deadlock/OOM. Runner ini membangun + menjalankan unit test C
# portabel:
#   1. proc_flood    -- deadlock stdin/stdout, flood 100MiB prefix+tail,
#                      env override (MYC-AUDIT-002/017 + bounded capture).
#   2. oom_guards    -- guard overflow arena + input ekstrem.
#   3. oom_alloc     -- injeksi kegagalan malloc/calloc/realloc (--wrap),
#                      incl. fase JSON (MYC-AUDIT-009 sb_reserve/obj_set).
#   4. stress_threads-- concurrency myc_run paralel (Fase 5, juga Windows).
#   5. audit_lampiran-- lampiran A: exec-vs-127, temp path, contract panjang,
#                      NUL portability, 0 driver cases, immutable, fp-long
#                      (T8), file_path-only (T9), canary failure (T11),
#                      + varian ASan untuk fp-long (AUDIT-005 OOB).
#   6. filc gate     -- uji gate --filc bila filc-clang tersedia di PATH
#                      (ok_filc → L5 FILC, bad_filc_oob → FILC_VIOLATION).
#
# Dijalankan dari _regress_run.bat (bila bash tersedia) atau langsung di
# POSIX/CI Linux. CWD harus root proyek.
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

SRCS="myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c"
CC="${CC:-gcc}"
# POSIX/Windows butuh -pthread untuk stress_threads (pthread_create/join).
# Deteksi apakah kompiler menerima flag; aman untuk MinGW juga.
PTHREAD=""
if "$CC" -pthread -o /dev/null -x c - 2>/dev/null <<'EOF'
int main(void){return 0;}
EOF
then
    PTHREAD="-pthread"
fi
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
if $CC -O2 -std=c11 -Wall -Wextra -I. $PTHREAD -o test/proc_flood test/proc_flood.c proc.c 2>/dev/null; then
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
if $CC -O2 -std=c11 -Wall -Wextra -I. $PTHREAD -DMYC_NO_MAIN -o test/stress_threads \
       test/stress_threads.c $SRCS 2>/dev/null; then
    run_built "audit018 stress_threads (concurrency)" test/stress_threads
else
    echo "[FAIL] audit018 stress_threads gagal dibangun"
    FAIL=1
fi

# --- 5. verify_descendants: MYC-AUDIT-011 (POSIX-only: butuh fork) ---
# Grandchild yang di-fork child harus ikut mati saat myc membunuh process
# group pada timeout. MinGW/MSYS/CYGWIN tidak menyediakan fork() -> skip.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        echo "[SKIP] audit018 verify_descendants (POSIX-only, fork tak tersedia)"
        ;;
    *)
        if $CC -O2 -std=c11 -Wall -Wextra -I. -o test/verify_descendants \
               test/verify_descendants.c proc.c 2>/dev/null; then
            run_built "audit018 verify_descendants (group kill mematikan descendant)" \
                      test/verify_descendants
        else
            echo "[FAIL] audit018 verify_descendants gagal dibangun"
            FAIL=1
        fi
        ;;
esac

# --- 6. audit_lampiran: lampiran A roadmap (regression test portabel) ---
rm -f test/audit_lampiran test/audit_lampiran.exe
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/audit_lampiran \
       test/audit_lampiran.c $SRCS 2>/dev/null; then
    run_built "audit_lampiran (gap lampiran A: exec/contract/run)" test/audit_lampiran
else
    echo "[FAIL] audit_lampiran gagal dibangun"
    FAIL=1
fi

# --- 6b. Varian ASan untuk T8 (fp-long): menangkap OOB read regresi
# MYC-AUDIT-005 secara EKSPLISIT. Butuh toolchain dengan -fsanitize=address
# (mis. clang/gcc WSL); MinGW Windows biasanya tak punya ASan runtime ->
# skip (bukan klaim). Bila ASan tersedia dan fingerprint memicu OOB read,
# proses akan di-abort ASan (exit 1) -> run_built menandai FAIL. ---
if $CC -fsanitize=address -o /dev/null -x c - 2>/dev/null <<'EOF'
int main(void){return 0;}
EOF
then
    if $CC -O1 -g -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
           -fsanitize=address -fno-omit-frame-pointer \
           -o test/audit_lampiran_asan test/audit_lampiran.c $SRCS 2>/dev/null; then
        run_built "audit_lampiran fp-long ASan (AUDIT-005 OOB)" \
                  test/audit_lampiran_asan --fp-long
    else
        echo "[FAIL] audit_lampiran fp-long ASan gagal dibangun"
        FAIL=1
    fi
else
    echo "[SKIP] audit_lampiran fp-long ASan (toolchain ASan tak tersedia)"
fi

rm -f test/proc_flood test/proc_flood.exe test/oom_guards test/oom_guards.exe \
      test/oom_alloc test/oom_alloc.exe test/stress_threads test/stress_threads.exe \
      test/verify_descendants test/verify_descendants.exe \
      test/audit_lampiran test/audit_lampiran.exe \
      test/audit_lampiran_asan test/audit_lampiran_asan.exe

# --- 6c. Fil-C gate (jika filc-clang tersedia di PATH) ---
if command -v filc-clang >/dev/null 2>&1 && [ -x ./myc ]; then
    # MYC-AUDIT-023: jangan pakai run_built (cek EXIT code) untuk fixture
    # bad_filc_oob — verdict FILC_VIOLATION memang keluar exit 1 (benar).
    # Assert via output, bukan exit code.
    if ./myc check test/fixtures/ok_filc.c --filc 2>&1 | grep -q "verdict:   OK"; then
        echo "[OK] filc ok_filc --filc (L5 FILC)"
    else
        echo "[FAIL] filc ok_filc --filc (L5 FILC)"
        FAIL=1
    fi
    if ./myc check test/fixtures/bad_filc_oob.c --filc --run 2>&1 | grep -q "FILC_VIOLATION"; then
        echo "[OK] filc bad_filc_oob --filc --run (FILC_VIOLATION)"
    else
        echo "[FAIL] filc bad_filc_oob --filc --run (FILC_VIOLATION)"
        FAIL=1
    fi
    # MYC-AUDIT-024 (roadmap 7.7): version identity + robust report parser
    # (per-case scope). Parser struktural: baris kanonik "[pid] filc panic:",
    # detail message + lokasi origin (file:line:col: func) tiap panic.
    if ./myc check test/fixtures/ok_filc.c --filc 2>&1 | grep -q "version: clang version"; then
        echo "[OK] filc version identity (7.7)"
    else
        echo "[FAIL] filc version identity (7.7)"
        FAIL=1
    fi
    if ./myc check test/fixtures/bad_filc_oob.c --filc 2>&1 | grep -q "case #1:"; then
        echo "[OK] filc per-case scope (7.7)"
    else
        echo "[FAIL] filc per-case scope (7.7)"
        FAIL=1
    fi
else
    echo "[SKIP] filc-clang tidak tersedia di PATH atau myc binary tidak ditemukan"
fi

rm -f test/filc_test test/filc_test.exe

echo "audit018: $([ $FAIL -eq 0 ] && echo SELESAI OK || echo GAGAL)"
exit $FAIL
