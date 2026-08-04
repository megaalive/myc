#!/usr/bin/env bash
# =====================================================================
# _ci_linux.sh -- Trust-core runner POSIX (Linux CI via GitHub Actions,
#                dan setara untuk WSL / pengembangan Linux lokal).
#
# Mirror ringkas _regress_run.bat untuk platform tanpa cmd.exe. Menguji
# invariants inti myc pada Linux:
#   1. build.sh (myc/mcp/argv_probe)
#   2. self-dogfooding: 16 source myc harus verdict OK
#   3. fixture kunci: ok_hello OK; bad_syntax/bad_realloc COMPILE_ERROR;
#      diagnostic JSON machine-readable (MYC-AUDIT-022)
#   4. exact tool identity: `myc version` cetak versi gcc/clang (AUDIT-022)
#   5. checked build: ok_checked L4; bad_checked COMPILE_ERROR
#   6. verification run (WAJIB clang ASan): ok_run L3; bad_run_oob
#      RUNTIME_VIOLATION; receipt deterministik lintas-run (bukan golden —
#      receipt memuat fingerprint berisi gcc_path, jadi bersifat mesin-spesifik)
#   7. dogfood tool (ring/config/tilemap)
#   8. json_abuse corpus; audit018 (deadlock/OOM/concurrency/fork)
#
# Non-blocking oleh desain (MYC-AUDIT-004/9.10): Frama-C (--prove) dan
# Fil-C (--filc) TIDAK diinstall di CI Linux -> fixture prove/filc
# menampilkan UNAVAILABLE (bukan FAIL). Backend yang WAJIB ada: gcc + clang.
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

FAIL=0
PASS=0

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=1; }

assert_out() { # assert_out <desc> <pattern> <file> [flags...]
    local desc="$1" want="$2" file="$3"
    shift 3
    if ./myc check "$file" "$@" 2>&1 | grep -qF "$want"; then
        note "$desc"
    else
        echo "[FAIL] $desc (output tidak memuat: $want)"
        FAIL=1
    fi
}

# --- 0. build ---
# Panggil via `bash` (bukan ./build.sh): executable bit TIDAK dijamin
# ter-set di repo Windows (core.filemode=false) sehingga `./build.sh`
# gagal Permission denied di Linux CI (ext4). WSL/drvfs mengabaikan bit.
if bash build.sh >/dev/null 2>&1; then
    note "build.sh (myc/mcp/argv_probe)"
else
    echo "[FAIL] build.sh"
    exit 1
fi

# --- 1. self-dogfooding ---
for f in myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c \
         run.c contract.c prove.c filc.c driver.c json.c mcp.c negative.c; do
    if ./myc check "$f" 2>&1 | grep -qF "verdict:   OK"; then
        :
    else
        echo "[FAIL] self-dogfood $f"
        FAIL=1
    fi
done
[ "$FAIL" -eq 0 ] && note "self-dogfooding 16 source myc"

# --- 2. fixture dasar + diagnostic JSON (AUDIT-022) ---
assert_out "ok_hello -> OK"               "verdict:   OK" tests/ok_hello.c
assert_out "bad_syntax -> COMPILE_ERROR"  "verdict:   COMPILE_ERROR" tests/bad_syntax.c
assert_out "bad_realloc -> COMPILE_ERROR" "verdict:   COMPILE_ERROR" tests/bad_realloc.c
# Pesan gcc: gcc 13 (Linux) memakai tanda kutip Unicode ' ' sedangkan gcc
# 15 (MinGW) memakai ASCII ' ' -> pola regex harus cocok untuk keduanya.
if ./myc check tests/bad_realloc.c 2>&1 | grep -qE "used after .realloc"; then
    note "diagnostic JSON machine-readable"
else
    fail "diagnostic JSON machine-readable"
fi

# --- 3. exact tool identity (AUDIT-022) ---
if ./myc version 2>&1 | grep -qF "gcc version:"; then
    note "myc version cetak gcc version"
else
    fail "myc version gcc version hilang"
fi
if ./myc version 2>&1 | grep -qF "clang version:"; then
    note "myc version cetak clang version"
else
    fail "myc version clang version hilang"
fi

# --- 4. checked build (L4) ---
assert_out "ok_checked --checked -> L4" "assurance: L4" tests/ok_checked.c --checked
assert_out "bad_checked --checked -> COMPILE_ERROR" "verdict:   COMPILE_ERROR" tests/bad_checked.c --checked

# --- 4b. checked coverage + semantics parity (MYC-AUDIT-026, roadmap 7.3) ---
if ./myc check tests/semantics_parity.c --checked 2>&1 | grep -qF \
    "buffers=2 allocations=2 accesses=6 frees=2"; then
    note "checked coverage count (2 buffer, 6 titik akses)"
else
    fail "checked coverage count"
fi
assert_out "semantics_parity --checked -> L4" "assurance: L4" tests/semantics_parity.c --checked
# No over-claim: komentar berisi "MYC_BUF" TIDAK boleh memicu coverage/L4
if ./myc check tests/checked_comment_only.c --checked 2>&1 | grep -qF "checked build di-skip" &&
   ! ./myc check tests/checked_comment_only.c --checked 2>&1 | grep -qF "  build_ok:"; then
    note "comment-only MYC_BUF di-skip (no over-claim)"
else
    fail "comment-only MYC_BUF over-claim"
fi
# Semantics parity: source sama, build produksi vs -DMYC_CHECKED=1, output identik
if gcc -O2 -std=c11 -Wall -I. -o test/parity_prod tests/semantics_parity.c 2>/dev/null &&
   gcc -O2 -std=c11 -Wall -I. -DMYC_CHECKED=1 -o test/parity_ck tests/semantics_parity.c 2>/dev/null; then
    test/parity_prod > test/parity_prod.txt; PEC=$?
    test/parity_ck  > test/parity_ck.txt;  CEC=$?
    if [ "$PEC" -eq 0 ] && [ "$CEC" -eq 0 ] && cmp -s test/parity_prod.txt test/parity_ck.txt; then
        note "semantics parity: stdout + exit identik (produksi vs checked)"
    else
        fail "semantics parity (prod=$PEC ck=$CEC)"
    fi
else
    fail "semantics parity build"
fi
rm -f test/parity_prod test/parity_ck test/parity_prod.txt test/parity_ck.txt

# --- 5. verification run (butuh clang ASan) ---
assert_out "ok_run --run -> L3" "assurance: L3" tests/ok_run.c --run
assert_out "bad_run_oob --run -> RUNTIME_VIOLATION" "verdict:   RUNTIME_VIOLATION" tests/bad_run_oob.c --run

# --- 5b. receipt deterministik lintas-run (invariant portabel) ---
R1=$(./myc check tests/ok_run.c --run 2>&1 | sed -n 's/.*receipt_sha256: //p' | head -1)
R2=$(./myc check tests/ok_run.c --run 2>&1 | sed -n 's/.*receipt_sha256: //p' | head -1)
if [ -n "$R1" ] && [ "$R1" = "$R2" ]; then
    note "receipt deterministik lintas-run (${R1:0:8}...)"
else
    fail "receipt tidak deterministik ($R1 vs $R2)"
fi

# --- 6. dogfood tool ---
for f in dogfood/dogfood_ring.c dogfood/dogfood_config.c dogfood/dogfood_tilemap.c; do
    assert_out "dogfood $(basename "$f") -> OK" "verdict:   OK" "$f"
done

# --- 7. json_abuse corpus ---
if gcc -O2 -std=c11 -Wall -Wextra -I. -o test/json_abuse test/json_abuse.c json.c 2>/dev/null &&
   test/json_abuse | grep -qF "OK"; then
    note "json_abuse corpus ketat"
else
    fail "json_abuse corpus"
fi
rm -f test/json_abuse

# --- 8. audit018 (deadlock/OOM/concurrency/fork/descendants) ---
if bash test/_audit018.sh; then
    note "audit018 SELESAI OK"
else
    fail "audit018"
fi

echo "=== _ci_linux.sh: PASS=$PASS FAIL=$FAIL ==="
exit $FAIL
