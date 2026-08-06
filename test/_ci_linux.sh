#!/usr/bin/env bash
# =====================================================================
# _ci_linux.sh -- Trust-core runner POSIX (Linux CI via GitHub Actions,
#                dan setara untuk WSL / pengembangan Linux lokal).
#
# Mirror ringkas _regress_run.bat untuk platform tanpa cmd.exe. Menguji
# invariants inti myc pada Linux:
#   1. build.sh (myc/mcp/argv_probe)
#   2. self-dogfooding: 23 source myc harus verdict OK
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
# Output build TIDAK disembunyikan: bila gagal, error gcc harus terlihat di
# log CI (sebelumnya disembunyikan -> [FAIL] build.sh tanpa penyebab).
bash build.sh > /tmp/myc_build.log 2>&1
BUILD_RC=$?
if [ $BUILD_RC -eq 0 ]; then
    note "build.sh (myc/mcp/argv_probe)"
else
    echo "[FAIL] build.sh (rc=$BUILD_RC)"; tail -30 /tmp/myc_build.log
    exit 1
fi

# --- 0b. capabilities registry sync (SOL-23) ---
if bash test/_cap_sync.sh; then
    note "capabilities registry sinkron (capabilities.json vs source+docs)"
else
    fail "capabilities registry sync"
fi

# --- 0c. pre-flight: prove.c compile dengan -Werror (MYC-AUDIT-023) ---
# prove.c adalah kantor terdepan untuk -Werror karena WSL/Frama-C code.
# Jika gagal di sini, fail-fast dengan pesan jelas.
if ! gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -Werror=implicit-function-declaration -c prove.c -o /tmp/prove_preflight.o 2>&1; then
    echo "[FAIL] pre-flight prove.c -Werror (lihat error di atas)"
    FAIL=1
else
    note "pre-flight prove.c -Werror clean"
fi

# --- 1. self-dogfooding ---
for f in myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c \
         run.c contract.c prove.c filc.c driver.c json.c mcp.c negative.c \
         agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c; do
    if ./myc check "$f" 2>&1 | grep -qF "verdict:   OK"; then
        :
    else
        echo "[FAIL] self-dogfood $f"
        FAIL=1
    fi
done
[ "$FAIL" -eq 0 ] && note "self-dogfooding 23 source myc"

# --- 1b. --json-summary mode (ringkas untuk agent) ---
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"verdict":"OK"'; then
    note "--json-summary verdict OK"
else
    fail "--json-summary verdict missing"
fi
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"assurance_vector"'; then
    note "--json-summary assurance_vector ada"
else
    fail "--json-summary assurance_vector hilang"
fi
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"receipt_sha256"'; then
    note "--json-summary receipt_sha256 ada"
else
    fail "--json-summary receipt_sha256 hilang"
fi
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"diagnostics"'; then
    note "--json-summary diagnostics ada"
else
    fail "--json-summary diagnostics hilang"
fi
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"gate_matrix"'; then
    note "--json-summary gate_matrix ada"
else
    fail "--json-summary gate_matrix hilang"
fi
# pastikan field besar TIDAK muncul di summary
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"stdout_text"'; then
    fail "--json-summary seharusnya tidak mengandung stdout_text"
else
    note "--json-summary tidak mengandung stdout_text"
fi
if ./myc check tests/ok_hello.c --json-summary 2>&1 | grep -qF '"stderr_text"'; then
    fail "--json-summary seharusnya tidak mengandung stderr_text"
else
    note "--json-summary tidak mengandung stderr_text"
fi

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

# --- 5c. driver: case record + combinatorial budget + harness sha (AUDIT-027) ---
if ./myc check test/fixtures/ok_driver.c --driver 2>&1 | grep -qF \
    "combinatorial: max_product=5 budget=32 strategy=full"; then
    note "driver combinatorial full utk produk kecil"
else
    fail "driver combinatorial full"
fi
if ./myc check test/fixtures/ok_driver.c --driver 2>&1 | grep -qF \
    "harness_sha256:"; then
    note "driver harness_sha256 di laporan"
else
    fail "driver harness_sha256 hilang"
fi
if ./myc check test/fixtures/ok_driver.c --driver 2>&1 | grep -qF \
    "#1   ok_sum"; then
    note "driver case record #1 berisi input+status"
else
    fail "driver case record hilang"
fi
if ./myc check test/fixtures/ok_driver_bounded.c --driver 2>&1 | grep -qF \
    "strategy=coverage-first"; then
    note "driver coverage-first utk produk besar"
else
    fail "driver coverage-first tidak muncul"
fi
if ./myc check test/fixtures/ok_driver_bounded.c --driver 2>&1 | grep -qF \
    "combinatorial: max_product=64 budget=32"; then
    note "driver max_product+budget jujur (64>32)"
else
    fail "driver max_product/budget hilang"
fi
assert_out "ok_driver --driver -> L3" "assurance: L3" test/fixtures/ok_driver.c --driver
assert_out "bad_driver_oob --driver -> DRIVER_VIOLATION" "verdict:   DRIVER_VIOLATION" test/fixtures/bad_driver_oob.c --driver
if ./myc check test/fixtures/driver_zero_cases.c --driver 2>&1 | grep -qF \
    "generated driver diminta tapi 0 kasus"; then
    note "driver 0 kasus -> debt NONZERO_CASES"
else
    fail "driver debt NONZERO_CASES hilang"
fi

# --- 5d. size cap saat membaca (MYC-AUDIT-028, Fase 2) ---
BIGSRC=$(mktemp -u /tmp/myc_big_028_XXXX.c)
BIGRUN=$(mktemp -u /tmp/myc_bigstdin_028_XXXX.bin)
dd if=/dev/zero of="$BIGSRC" bs=1M count=2 status=none
dd if=/dev/zero of="$BIGRUN" bs=1M count=10 status=none
if ./myc check "$BIGSRC" >/dev/null 2>&1; then
    fail "source >1MiB tidak ditolak"
else
    if ./myc check "$BIGSRC" 2>&1 | grep -qF "melebihi cap 1048576"; then
        note "source >1MiB ditolak cap saat membaca (exit!=0)"
    else
        fail "pesan cap source hilang"
    fi
fi
if ./myc check test/fixtures/ok_run.c --run --run-stdin "$BIGRUN" >/dev/null 2>&1; then
    fail "run-stdin >8MiB tidak ditolak"
else
    if ./myc check test/fixtures/ok_run.c --run --run-stdin "$BIGRUN" 2>&1 | \
        grep -qF "melebihi cap 8388608"; then
        note "run-stdin >8MiB ditolak cap saat membaca"
    else
        fail "pesan cap run-stdin hilang"
    fi
fi
rm -f "$BIGSRC" "$BIGRUN"

# --- 5e. canonicalisasi path cwd (MYC-AUDIT-030, Fase 2) ---
C1=$(./myc check tests/ok_hello.c --cwd tests 2>&1 | grep 'cwd:' | tr -d ' ')
C2=$(./myc check tests/ok_hello.c --cwd "tests/../tests" 2>&1 | grep 'cwd:' | tr -d ' ')
C3=$(./myc check tests/ok_hello.c --cwd "./tests" 2>&1 | grep 'cwd:' | tr -d ' ')
C4=$(./myc check tests/ok_hello.c --cwd . 2>&1 | grep 'cwd:' | tr -d ' ')
if [ -z "$C1" ]; then
    fail "cwd canonical: baris cwd: tak tertangkap"
elif [ "$C1" = "$C2" ] && [ "$C1" = "$C3" ]; then
    note "cwd canonical: tests/../tests dan ./tests IDENTIK"
else
    fail "cwd canonical: ejaan berbeda tapi cwd tak identik (C1=$C1 C2=$C2 C3=$C3)"
fi
if [ "$C1" != "$C4" ]; then
    note "cwd berbeda -> cwd canonical BERBEDA"
else
    fail "cwd berbeda justru sama"
fi
unset C1 C2 C3 C4

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
