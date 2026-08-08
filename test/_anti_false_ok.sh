#!/usr/bin/env bash
# =====================================================================
# _anti_false_ok.sh -- Guard anti-false-OK (MYC-AUDIT-031) versi POSIX.
#
# Mirror portabel dari test/_anti_false_ok.bat untuk CI Linux / WSL.
#
# Pastikan myc BENAR-BENAR menjalankan gcc/sanitizer dan menolak input
# rusak. Sejarah: bug STARTUPINFOEX membuat peluncuran gcc gagal
# diam-diam di Windows, namun gerbang preprocess/compile/analyzer
# mengabaikan nilai kembalian myc_proc_run sehingga program RUSAK
# dilaporkan "verdict: OK" (false-OK). Guard ini gagal (exit 1) bila
# fixture negatif tidak lagi menghasilkan verdict negatif.
#
# CWD harus root repo.
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

if [ -x ./myc.exe ]; then
    MYC="./myc.exe"
else
    MYC="./myc"
fi

FAIL=0
PASS=0

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=1; }

expect() { # expect <file> <flags...> <want> <desc>
    local file="$1" want="$2" desc="$3"
    shift 3
    if "$MYC" check "$file" "$@" 2>&1 | grep -qF "$want"; then
        note "$desc (memuat: $want)"
    else
        fail "$desc -- diharapkan mengandung '$want'"
    fi
}

echo "=== Anti-false-OK guard (MYC-AUDIT-031, POSIX) ==="

expect tests/bad_syntax.c COMPILE_ERROR "basic syntax error" --no-lint
expect tests/bad_oob.c COMPILE_ERROR "basic OOB gcc memory tier" --no-lint
expect tests/bad_realloc.c COMPILE_ERROR "basic realloc UAF" --no-lint
expect tests/bad_checked.c COMPILE_ERROR "checked direct b[i]" --checked
expect tests/bad_run_oob.c RUNTIME_VIOLATION "run OOB via ASan" --run
expect tests/ok_run.c "verdict:   OK" "run ok_run stays OK" --run

if [ "$FAIL" = "0" ]; then
    note "anti-false-OK guard lulus"
else
    fail "anti-false-OK guard GAGAL"
fi

echo "=== _anti_false_ok.sh: PASS=$PASS FAIL=$FAIL ==="
exit $FAIL
