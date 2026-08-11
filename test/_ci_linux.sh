#!/usr/bin/env bash
# =====================================================================
# _ci_linux.sh -- Trust-core runner POSIX (Linux CI via GitHub Actions,
#                dan setara untuk WSL / pengembangan Linux lokal).
#
# Mirror ringkas _regress_run.bat untuk platform tanpa cmd.exe. Menguji
# invariants inti myc pada Linux:
#   1. build.sh (myc/mcp/argv_probe)
#   2. self-dogfooding: 24 source myc harus verdict OK
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
          agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c; do
    if ./myc check "$f" 2>&1 | grep -qF "verdict:   OK"; then
        :
    else
        echo "[FAIL] self-dogfood $f"
        FAIL=1
    fi
done
[ "$FAIL" -eq 0 ] &&     note "self-dogfooding 26 source myc"

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

# --- 4a. raw buffers di luar MYC_BUF (MYC-AUDIT-040) ---
if ./myc check tests/raw_buf_mixed.c --checked 2>&1 | grep -qF "MYC-INCOMPLETE-RAW-BUFFERS"; then
    note "raw_buf_mixed: buffer biasa di luar MYC_BUF -> debt RAW-BUFFERS"
else
    fail "raw_buf_mixed: debt RAW-BUFFERS tidak muncul"
fi
if ./myc check tests/raw_buf_mixed.c --checked --require-complete 2>&1 | grep -qF "verdict:   INCONCLUSIVE"; then
    note "raw_buf_mixed --require-complete: gap raw-buffers -> INCONCLUSIVE"
else
    fail "raw_buf_mixed --require-complete: gap tidak menggagalkan hasil"
fi
if ./myc check tests/semantics_parity.c --checked 2>&1 | grep -qF "MYC-INCOMPLETE-RAW-BUFFERS"; then
    fail "semantics_parity murni MYC_BUF kena debt RAW-BUFFERS (false positive)"
else
    note "semantics_parity: tanpa raw buffer, tanpa debt"
fi
if ./myc check tests/ok_checked.c --checked 2>&1 | grep -qF "MYC-INCOMPLETE-RAW-BUFFERS"; then
    fail "ok_checked kena debt RAW-BUFFERS (false positive)"
else
    note "ok_checked: tanpa raw buffer, tanpa debt"
fi

# --- 4a2. INFRA-FAILED: backend ADA tapi gagal (MYC-AUDIT-041) ---
# Regresi audit debt: myc_filc_gate men-set INFRA_FAILED (build gagal);
# compile.c harus MEMPERTAHANKAN status itu (dulu ditimpa jadi UNAVAILABLE
# sehingga MYC-INCOMPLETE-GATE-INFRA-FAILED tak pernah bisa muncul).
if ./myc check tests/ok_hello.c --filc --no-cache 2>&1 | grep -qF "MYC-INCOMPLETE-GATE-UNAVAILABLE"; then
    note "ok_hello --filc (tanpa backend): debt GATE-UNAVAILABLE"
else
    fail "ok_hello --filc: debt GATE-UNAVAILABLE tidak muncul"
fi
FAKEBIN=$(mktemp -d)
printf 'int main(void){return 3;}\n' > "$FAKEBIN/fc.c"
gcc -O0 -o "$FAKEBIN/filc-clang" "$FAKEBIN/fc.c" 2>/dev/null
gcc -O0 -o "$FAKEBIN/filc-clang.exe" "$FAKEBIN/fc.c" 2>/dev/null
if PATH="$FAKEBIN:$PATH" ./myc check tests/ok_hello.c --filc --no-cache 2>&1 | grep -qF "MYC-INCOMPLETE-GATE-INFRA-FAILED"; then
    note "ok_hello --filc (backend gagal): debt GATE-INFRA-FAILED dipertahankan"
else
    fail "ok_hello --filc: debt GATE-INFRA-FAILED tidak muncul (status ditimpa?)"
fi
rm -rf "$FAKEBIN"

# --- 4a3. cache replay identik + JSON round-trip (MYC-AUDIT-042) ---
# Replay harus menampilkan teks debt yang SAMA dgn run asli (dulu ditimpa
# nama kode), dan file cache dengan byte non-UTF8 dari stderr backend harus
# tetap bisa di-parse ulang (dulu rusak -> cache-hit flaky).
rm -rf .myc
./myc check test/fixtures/driver_zero_cases.c --driver >/dev/null 2>&1
if ./myc check test/fixtures/driver_zero_cases.c --driver 2>&1 | grep -q "cache:     hit"; then
    note "4a3 cache replay: run2 cache-hit stabil (JSON round-trip non-UTF8)"
else
    fail "4a3 cache replay: run2 tidak cache-hit (round-trip JSON rusak?)"
fi
if ./myc check tests/ok_hello.c --filc 2>&1 | grep -q "gate diminta tapi backend tidak tersedia"; then
    note "4a3 cache replay: debt text identik dgn fresh run"
else
    fail "4a3 cache replay: debt text hilang/ditimpa di replay"
fi
rm -rf .myc

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

# --- 5f. B4 Comments-as-Contracts (DS-08): harvest komentar biasa ---
if ./myc check test/fixtures/harvest_contracts.c --no-cache 2>&1 | grep -qF "harvest (B4): 6 kandidat komentar-biasa, 5 validated"; then
    note "B4 harvest: 6 kandidat, 5 validated"
else
    fail "B4 harvest: kandidat/validated salah"
fi
if ./myc check test/fixtures/harvest_contracts.c --no-cache 2>&1 | grep -qF "requires clamp_len: \`len <= cap\` -- validated"; then
    note "B4 harvest: pola 'must be <=' ke kontrak requires"
else
    fail "B4 harvest: pola 'must be <=' tidak terdeteksi"
fi
if ./myc check test/fixtures/harvest_contracts.c --no-cache 2>&1 | grep -qF "perlu //@ syntax (bukan C murni)"; then
    note "B4 harvest: prose non-C ditolak (perlu //@ syntax)"
else
    fail "B4 harvest: prose non-C tidak ditolak"
fi
if ./myc check test/fixtures/harvest_contracts.c --no-cache --json-summary 2>&1 | grep -qF '"harvest":{"candidates":6,"validated":5,"unbound":0}'; then
    note "B4 harvest di --json-summary"
else
    fail "B4 harvest hilang di --json-summary"
fi
if ./myc check test/fixtures/harvest_contracts.c --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "B4 harvest non-blocking (verdict tetap OK)"
else
    fail "B4 harvest mengubah verdict (harus non-blocking)"
fi

# --- 5g. A3 Small-Domain Exhaustive Proof (DS-03) ---
rm -f .myc/exhaustive.json
if ./myc check test/fixtures/ok_exhaustive.c --exhaustive --no-cache 2>&1 | grep -qF "P1 EXHAUSTIVE untuk domain dideklarasikan"; then
    note "A3 exhaustive: P1 EXHAUSTIVE pada domain 0..64 (65 titik)"
else
    fail "A3 exhaustive: P1 EXHAUSTIVE tidak tercapai"
fi
if ./myc check test/fixtures/bad_exhaustive.c --exhaustive --no-cache 2>&1 | grep -qF "counterexample ditemukan"; then
    note "A3 exhaustive: counterexample terdeteksi pada ensures salah"
else
    fail "A3 exhaustive: counterexample tidak terdeteksi"
fi
if ./myc check test/fixtures/exhaustive_wide.c --exhaustive --no-cache 2>&1 | grep -qF "terlalu lebar"; then
    note "A3 DS-03 firewall: domain lebar ditolak (bukan exhaustive)"
else
    fail "A3 DS-03 firewall: domain lebar tidak ditolak"
fi
if ./myc check test/fixtures/exhaustive_narrow.c --exhaustive --no-cache 2>&1 | grep -qF "SCOPE_LAUNDERING"; then
    note "A3 DS-03: SCOPE_LAUNDERING terdeteksi setelah domain dipersempit"
else
    fail "A3 DS-03: SCOPE_LAUNDERING tidak terdeteksi"
fi
rm -f .myc/exhaustive.json

# --- 5g. B3 LLM Error Taxonomy + coaching transcript (DS-07) ---
if ./myc check tests/bad_realloc.c --no-cache 2>&1 | grep -qF "coaching (B3): 2 item taksonomi"; then
    note "B3 coaching: finding diklasifikasi kognitif"
else
    fail "B3 coaching: taksonomi tidak muncul"
fi
if ./myc check tests/bad_realloc.c --no-cache 2>&1 | grep -qF "[missing_guard]"; then
    note "B3 coaching: kelas missing_guard terdeteksi"
else
    fail "B3 coaching: kelas kognitif hilang"
fi
if ./myc check tests/bad_realloc.c --no-cache 2>&1 | grep -qF "strategi: Tambahkan guard"; then
    note "B3 coaching: strategi per kelas ada"
else
    fail "B3 coaching: strategi hilang"
fi
if ./myc check tests/bad_realloc.c --no-cache 2>&1 | grep -qF "verdict:   COMPILE_ERROR"; then
    note "B3 coaching non-blocking (verdict tetap COMPILE_ERROR)"
else
    fail "B3 coaching mengubah verdict"
fi
if ./myc check tests/bad_realloc.c --no-cache --json-summary 2>&1 | grep -qF '"coaching":[{"class":"missing_guard"'; then
    note "B3 coaching di --json-summary"
else
    fail "B3 coaching hilang di --json-summary"
fi
if ! ./myc check tests/ok_hello.c --no-cache 2>&1 | grep -qF "coaching (B3)"; then
    note "B3 tanpa finding = tanpa coaching"
else
    fail "B3 coaching muncul pada source bersih"
fi

# --- 5h. D4 System-Prompt Contract Generator (myc prompt, DS-15) ---
if ./myc prompt tests/ok_hello.c 2>&1 | grep -qF "# Aturan C untuk proyek ini (dari myc -- deterministik"; then
    note "D4 prompt: header deterministik muncul"
else
    fail "D4 prompt: header hilang"
fi
if ./myc prompt tests/ok_hello.c 2>&1 | grep -qF "Target host (fakta gcc host): char="; then
    note "D4 prompt: fakta target host ada"
else
    fail "D4 prompt: fakta target host hilang"
fi
if ./myc prompt tests/bad_system.c 2>&1 | grep -qF "Fungsi denylist dipanggil di file ini"; then
    note "D4 prompt: panggilan denylist terdeteksi"
else
    fail "D4 prompt: denylist tidak terdeteksi"
fi
if ./myc prompt tests/negative_dev.c 2>&1 | grep -qF "Konvensi alokasi (dari negative-space): 4/5"; then
    note "D4 prompt: konvensi alokasi dari negative-space"
else
    fail "D4 prompt: konvensi alokasi hilang"
fi
if ./myc prompt tests/ok_hello.c 2>&1 | grep -qF "Anti-churn"; then
    note "D4 prompt: aturan anti-churn ada"
else
    fail "D4 prompt: anti-churn hilang"
fi

# --- 5i. A4 Differential Oracle Pair (myc compare, DS-04) ---
if ./myc compare test/fixtures/ref_crc16.c test/fixtures/new_crc16_same.c 2>&1 | grep -qF "behavior-preserving (P1 DIFF) -- refactor aman"; then
    note "A4 compare: refactor yang sama perilakunya -> preserved"
else
    fail "A4 compare: behavior-preserving tidak terdeteksi"
fi
if ./myc compare test/fixtures/ref_crc16.c test/fixtures/new_crc16_div.c 2>&1 | grep -qF "unexpected_change (DS-04)"; then
    note "A4 compare: polinomial beda -> unexpected_change"
else
    fail "A4 compare: divergence tidak terdeteksi"
fi
if ./myc compare test/fixtures/ref_crc16.c test/fixtures/new_crc16_div.c 2>&1 | grep -qF "53 divergen"; then
    note "A4 compare: jumlah kasus divergen akurat"
else
    fail "A4 compare: jumlah divergen salah"
fi
if ./myc compare test/fixtures/ref_crc16.c test/fixtures/new_crc16_same.c 2>&1 | grep -qF "64 identik, 0 divergen"; then
    note "A4 compare: 64 kasus identik"
else
    fail "A4 compare: jumlah identik salah"
fi

# --- 5j. C2 Stack Budget Analyzer (--stack, DS-10) ---
if ./myc check tests/ok_hello.c --stack --no-cache 2>&1 | grep -qF "worst path : main = "; then
    note "C2 stack: worst path dihitung dari -fstack-usage"
else
    fail "C2 stack: worst path tidak terhitung"
fi
if ./myc check tests/ok_hello.c --stack-budget 10 --no-cache 2>&1 | grep -qF "melebihi budget"; then
    note "C2 stack: over budget terdeteksi (observasi)"
else
    fail "C2 stack: over budget tidak terdeteksi"
fi
if ./myc check test/fixtures/stack_recursive.c --stack --no-cache 2>&1 | grep -qF "recursion  : cycle di call graph"; then
    note "C2 stack: rekursi terdeteksi"
else
    fail "C2 stack: rekursi tidak terdeteksi"
fi
if ./myc check test/fixtures/stack_recursive.c --stack --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "C2 stack: non-blocking (verdict tetap OK)"
else
    fail "C2 stack: mengubah verdict (harus observasi)"
fi

# --- 5k. D1 Fuzz Gate fuzz-lite (--fuzz, DS-13) ---
if ./myc check test/fixtures/ok_fuzz.c --fuzz --fuzz-iters 2000 --no-cache 2>&1 | grep -qF "fuzz (D1): 1 fungsi, 2000 kasus tereksekusi"; then
    note "D1 fuzz: loop terikat tereksekusi penuh (seed deterministik)"
else
    fail "D1 fuzz: kasus fuzz tidak tereksekusi"
fi
if ./myc check test/fixtures/ok_fuzz.c --fuzz --fuzz-iters 2000 --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "D1 fuzz: source aman -> bersih"
else
    fail "D1 fuzz: source aman tidak bersih"
fi
if ./myc check test/fixtures/bad_fuzz.c --fuzz --fuzz-iters 2000 --no-cache 2>&1 | grep -qF "crash di peek_tbl"; then
    note "D1 fuzz: OOB terdeteksi (crash, seed reproduksibel)"
else
    fail "D1 fuzz: crash tidak terdeteksi"
fi
if ./myc check test/fixtures/bad_fuzz.c --fuzz --fuzz-iters 2000 --no-cache 2>&1 | grep -qF "DRIVER_VIOLATION"; then
    note "D1 fuzz: crash = bukti (DRIVER_VIOLATION)"
else
    fail "D1 fuzz: crash tidak menaikkan verdict"
fi

# --- 5l. B5 Mutation-Audited Verification (--mutate-audit, DS-09) ---
if ./myc check test/fixtures/mutate_target.c --mutate-audit --mutate-max 6 --no-cache 2>&1 | grep -qF "3 tertangkap, 0 GAP"; then
    note "B5 mutate: mutan guard tertangkap ASan (coverage 3/3)"
else
    fail "B5 mutate: mutan tidak tertangkap"
fi
if ./myc check test/fixtures/mutate_target.c --mutate-audit --mutate-max 6 --no-cache 2>&1 | grep -qF "verification coverage: 3/3"; then
    note "B5 mutate: verification coverage dihitung"
else
    fail "B5 mutate: coverage hilang"
fi
if ./myc check test/fixtures/mutate_target.c --mutate-audit --mutate-max 6 --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "B5 mutate: non-blocking (verdict tetap OK)"
else
    fail "B5 mutate: mengubah verdict (harus observasi)"
fi

# --- 5m. C1 Freestanding Mode (--freestanding) ---
if ./myc check test/fixtures/blinky_bad.c --freestanding --no-cache 2>&1 | grep -qF "printf() dipanggil -- API hosted"; then
    note "C1 freestanding: printf = trap API hosted"
else
    fail "C1 freestanding: hosted API trap tidak terdeteksi"
fi
if ./myc check test/fixtures/blinky_bad.c --freestanding --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "C1 freestanding: trap NON-blocking (verdict OK)"
else
    fail "C1 freestanding: mengubah verdict (harus observasi)"
fi
if ./myc check test/fixtures/blinky_clean.c --freestanding --no-cache 2>&1 | grep -qF "0 panggilan API hosted"; then
    note "C1 freestanding: firmware bersih -> hygiene bersih"
else
    fail "C1 freestanding: hygiene bersih tidak terdeteksi"
fi

# --- 5n. C3 MMIO/volatile/alignment traps (DS-11, mode freestanding) ---
if ./myc check test/fixtures/mmio_bad.c --freestanding --no-cache 2>&1 | grep -qF "MMIO deref alamat absolut tanpa volatile"; then
    note "C3 bare-metal: MMIO deref tanpa volatile terdeteksi"
else
    fail "C3 bare-metal: MMIO deref tidak terdeteksi"
fi
if ./myc check test/fixtures/mmio_bad.c --freestanding --no-cache 2>&1 | grep -qF "polling loop tanpa volatile"; then
    note "C3 bare-metal: polling loop tanpa volatile terdeteksi"
else
    fail "C3 bare-metal: polling loop tidak terdeteksi"
fi
if ./myc check test/fixtures/mmio_bad.c --freestanding --no-cache 2>&1 | grep -qF "cast uint8_t* ke tipe multi-byte"; then
    note "C3 bare-metal: alignment cast terdeteksi"
else
    fail "C3 bare-metal: alignment cast tidak terdeteksi"
fi
if ./myc check test/fixtures/mmio_bad.c --freestanding --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "C3 bare-metal: observasi NON-blocking (verdict tetap OK)"
else
    fail "C3 bare-metal: mengubah verdict (harus observasi)"
fi
if ./myc check test/fixtures/mmio_clean.c --freestanding --no-cache 2>&1 | grep -qF "bare-metal (C3/DS-11)"; then
    fail "C3 bare-metal: fixture bersih memunculkan observasi (false positive)"
else
    note "C3 bare-metal: idiom benar (volatile/READ_REG/memcpy) bersih"
fi
if ./myc check test/fixtures/mmio_bad.c --no-cache 2>&1 | grep -qF "MMIO deref alamat absolut tanpa volatile"; then
    fail "C3 bare-metal: rule aktif tanpa mode freestanding (harus tidak)"
else
    note "C3 bare-metal: rule hanya aktif di mode freestanding"
fi

# --- 5o. C5 Scenario Packs + D3 auto (DS-12) ---
if ./myc scenario list 2>&1 | grep -qF "firmware"; then
    note "C5 scenario: list memuat profil firmware"
else
    fail "C5 scenario: scenario list tidak memuat firmware"
fi
if ./myc scenario info firmware 2>&1 | grep -qF "stack_budget=4096"; then
    note "C5 scenario: env contract (DS-12) terlihat di info firmware"
else
    fail "C5 scenario: env DS-12 tidak terlihat di info firmware"
fi
if ./myc check test/fixtures/scen_parser.c --scenario auto --no-cache 2>&1 | grep -qF "scenario (C5): library"; then
    note "C5 scenario: auto menebak library (kontrak //@)"
else
    fail "C5 scenario: auto tidak menebak library"
fi
if ./myc check test/fixtures/mmio_bad.c --scenario auto --no-cache 2>&1 | grep -qF "scenario (C5): firmware"; then
    note "C5 scenario: auto menebak firmware (pola volatile/ISR)"
else
    fail "C5 scenario: auto tidak menebak firmware"
fi
if ./myc check tests/ok_hello.c --scenario cli-daily --no-cache 2>&1 | grep -qF "scenario (C5): cli-daily"; then
    note "C5 scenario: profil eksplisit diterapkan"
else
    fail "C5 scenario: profil eksplisit tidak diterapkan"
fi
if ./myc check tests/ok_hello.c --scenario bogus --no-cache 2>&1 | grep -qF "scenario tak dikenal"; then
    note "C5 scenario: nama tak dikenal = fail-fast"
else
    fail "C5 scenario: nama tak dikenal tidak ditolak"
fi

# --- 5p. C4 Target Matrix bare metal (--matrix) ---
if ./myc check tests/ok_hello.c --matrix --no-cache 2>&1 | grep -qF "matrix (C4):"; then
    note "C4 matrix: gate berjalan (host-only tanpa cross-compiler)"
else
    fail "C4 matrix: gate tidak berjalan"
fi
if ./myc check tests/ok_hello.c --matrix --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "C4 matrix: NON-blocking (verdict tetap OK)"
else
    fail "C4 matrix: mengubah verdict (harus observasi)"
fi
if ./myc check tests/ok_hello.c --matrix --no-cache --json-summary 2>&1 | grep -qF "\"matrix\":{"; then
    note "C4 matrix: hadir di JSON summary"
else
    fail "C4 matrix: hilang dari JSON summary"
fi

# --- 6a. Fase 6 Self-Challenge: Canary Swarm (myc canary) ---
if ./myc canary run 2>&1 | grep -qF "canary swarm: 11/11 PASS"; then
    note "Fase 6 canary: 11/11 canary PASS (semua backend terverifikasi hidup)"
else
    fail "Fase 6 canary: ada canary GAGAL (backend tidak terpercaya)"
fi
if ./myc canary list 2>&1 | grep -qF "11 canary untuk 9 backend"; then
    note "Fase 6 canary: registry 11 canary / 9 backend"
else
    fail "Fase 6 canary: registry canary tidak lengkap"
fi

# --- 6b. Fase 6 Self-Challenge: Test-Quality Audit (myc audit-tests) ---
if ./myc audit-tests 2>&1 | grep -qF "hazard class coverage: 7/7"; then
    note "Fase 6 audit-tests: 7/7 hazard class punya fixture"
else
    fail "Fase 6 audit-tests: hazard class ada gap"
fi
if ./myc audit-tests 2>&1 | grep -qF "[OK] exhaustive"; then
    note "Fase 6 audit-tests: semua backend punya fixture"
else
    fail "Fase 6 audit-tests: backend tanpa fixture"
fi

# --- 6c. Fase 6 Self-Challenge: Environment Perturbation (--perturb) ---
if ./myc check tests/ok_hello.c --run --perturb --no-cache 2>&1 | grep -qF "DETERMINISTIK lintas env"; then
    note "Fase 6 perturb: deterministik lintas 4 env (ok_hello)"
else
    fail "Fase 6 perturb: determinisme tidak terdeteksi"
fi
if ./myc check test/fixtures/pert_tz.c --run --perturb --no-cache 2>&1 | grep -qF "ENV-SENSITIVE"; then
    note "Fase 6 perturb: program env-sensitive (TZ) terdeteksi"
else
    fail "Fase 6 perturb: env-sensitive tidak terdeteksi"
fi

# --- 6d. Fase 6 Self-Challenge: Concurrency Probe (--thread-probe) ---
if ./myc check test/fixtures/con_inv.c --thread-probe --no-cache 2>&1 | grep -qF "LOCK-ORDER INVERSION"; then
    note "Fase 6 thread-probe: lock-order inversion terdeteksi"
else
    fail "Fase 6 thread-probe: inversion tidak terdeteksi"
fi
if ./myc check test/fixtures/con_inv.c --thread-probe --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "Fase 6 thread-probe: NON-blocking (verdict tetap OK)"
else
    fail "Fase 6 thread-probe: mengubah verdict (harus observasi)"
fi

# --- 6e. Fase 6 Self-Challenge: Regression Corpus (myc regression) ---
rm -rf .myc/regression
if ./myc check test/fixtures/fuzz_div0.c --fuzz --fuzz-iters 2000 --no-cache 2>&1 | grep -qF "verdict:   DRIVER_VIOLATION"; then
    note "Fase 6 regression: fuzz crash ditemukan (seed tersimpan)"
else
    fail "Fase 6 regression: fuzz crash tidak ditemukan"
fi
if ./myc regression list 2>&1 | grep -qF "seed ada"; then
    note "Fase 6 regression: counterexample tersimpan di corpus"
else
    fail "Fase 6 regression: seed tidak tersimpan"
fi
if ./myc regression run test/fixtures/fuzz_div0_fixed.c 2>&1 | grep -qF "RESOLVED"; then
    note "Fase 6 regression: fix tidak regress (seed -> RESOLVED)"
else
    fail "Fase 6 regression: fix tidak terdeteksi resolved"
fi
rm -rf .myc/regression

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

# --- 6f. Fase 2 Contract/domain delta (myc contract-delta) ---
if ./myc contract-delta test/fixtures/contract_wide.c test/fixtures/contract_narrow.c 2>&1 | grep -qF "NARROWED"; then
    note "Fase 2 contract-delta: domain menyempit terdeteksi (NARROWED, laundering)"
else
    fail "Fase 2 contract-delta: NARROWED tidak terdeteksi"
fi
if ./myc contract-delta test/fixtures/contract_wide.c test/fixtures/contract_wide.c 2>&1 | grep -qF "CLEAN"; then
    note "Fase 2 contract-delta: kontrak sama = CLEAN"
else
    fail "Fase 2 contract-delta: CLEAN tidak terdeteksi"
fi
if ./myc contract-delta test/fixtures/contract_wide.c test/fixtures/contract_narrow.c >/dev/null 2>&1; then
    fail "Fase 2 contract-delta: NARROWED harus exit != 0 (preservation dilanggar)"
else
    note "Fase 2 contract-delta: NARROWED exit=1 (preservation gate)"
fi

# --- 6g. Fase 5 Relational Contracts (klasifikasi klausa kontrak) ---
if ./myc check test/fixtures/relational_contracts.c --no-cache 2>&1 | grep -qF "5 relational (>=2 variabel), 1 unbound"; then
    note "Fase 5 relational: 5 relational + 1 unbound terdeteksi (fixture)"
else
    fail "Fase 5 relational: klasifikasi fixture salah"
fi
if ./myc check test/fixtures/relational_contracts.c --no-cache 2>&1 | grep -qF "[UNBOUND: identifier di luar param/return]"; then
    note "Fase 5 relational: identifier tak terikat (mystery) ditandai UNBOUND"
else
    fail "Fase 5 relational: UNBOUND tidak terdeteksi"
fi
if ./myc check test/fixtures/relational_contracts.c --json-summary --no-cache 2>&1 | grep -qF '"relational":{"analyzed":6,"relations":5,"unbound":1}'; then
    note "Fase 5 relational JSON summary: analyzed=6 relations=5 unbound=1"
else
    fail "Fase 5 relational JSON summary: angka salah"
fi
# round-trip: klasifikasi deterministik lintas run + contract-delta CLEAN
rt1=$(./myc check test/fixtures/relational_contracts.c --no-cache 2>&1 | grep "relational (Fase 5):" | sha256sum | cut -d' ' -f1)
rt2=$(./myc check test/fixtures/relational_contracts.c --no-cache 2>&1 | grep "relational (Fase 5):" | sha256sum | cut -d' ' -f1)
if [ -n "$rt1" ] && [ "$rt1" = "$rt2" ]; then
    note "Fase 5 relational round-trip: klasifikasi deterministik lintas run"
else
    fail "Fase 5 relational round-trip: run tidak deterministik"
fi
if ./myc contract-delta test/fixtures/relational_contracts.c test/fixtures/relational_contracts.c 2>&1 | grep -qF "CLEAN"; then
    note "Fase 5 relational round-trip: contract-delta sama file = CLEAN"
else
    fail "Fase 5 relational round-trip: contract-delta bukan CLEAN"
fi

# --- 6h. Fase 5 (SOL-13): State-Machine Ghosting (//@ sm) ---
if ./myc check test/fixtures/sm_protocol.c --no-cache 2>&1 | grep -qF "3 state, 4 event, 4 transisi, 0 finding"; then
    note "Fase 5 sm: mesin sehat = 0 finding (semua reachable + recovery)"
else
    fail "Fase 5 sm: mesin sehat tidak 0 finding"
fi
if ./myc check test/fixtures/sm_broken.c --no-cache 2>&1 | grep -qF "5 finding"; then
    note "Fase 5 sm: mesin rusak = 5 finding terdeteksi"
else
    fail "Fase 5 sm: mesin rusak tidak 5 finding"
fi
if ./myc check test/fixtures/sm_broken.c --no-cache 2>&1 | grep -qF "witness: IDLE --START--> BUSY --START--> STUCK"; then
    note "Fase 5 sm: witness urutan event terpendek (sink) benar"
else
    fail "Fase 5 sm: witness sequence salah"
fi
if ./myc check test/fixtures/sm_broken.c --no-cache 2>&1 | grep -qF "[unreachable]"; then
    note "Fase 5 sm: unreachable state terdeteksi"
else
    fail "Fase 5 sm: unreachable tidak terdeteksi"
fi
if ./myc sm test/fixtures/sm_protocol.c 2>&1 | grep -qF "ghost state machine"; then
    note "Fase 5 sm: subcommand myc sm berjalan"
else
    fail "Fase 5 sm: myc sm gagal"
fi

# --- 6i. Fase 5 (SOL-14): ABI/FFI Surface Certificate (--abi) ---
# Snapshot deterministik: dua run identik.
if ./myc abi snapshot test/fixtures/abi_stable.c > /tmp/abi_s1.txt 2>&1 && \
   ./myc abi snapshot test/fixtures/abi_stable.c > /tmp/abi_s2.txt 2>&1; then
    if cmp -s /tmp/abi_s1.txt /tmp/abi_s2.txt; then
        note "Fase 5 abi: snapshot deterministik (dua run identik)"
    else
        fail "Fase 5 abi: snapshot tidak deterministik"
    fi
else
    fail "Fase 5 abi: myc abi snapshot gagal"
fi
# Delta stable vs drift: 7 baris (layout/enum/symbol berubah).
./myc abi snapshot test/fixtures/abi_drift.c > /tmp/abi_b.txt 2>&1
if ./myc abi diff /tmp/abi_s1.txt /tmp/abi_b.txt 2>&1 | grep -qF "7 perubahan"; then
    note "Fase 5 abi: delta 7 baris (size/enum/symbol) terdeteksi"
else
    fail "Fase 5 abi: delta bukan 7 baris"
fi
if ./myc abi diff /tmp/abi_s1.txt /tmp/abi_b.txt 2>&1 | grep -qF "MEMBER Point z off=8"; then
    note "Fase 5 abi: offset member baru terdeteksi"
else
    fail "Fase 5 abi: offset member baru tidak terdeteksi"
fi
if ./myc check test/fixtures/abi_stable.c --abi --no-cache --json-summary 2>&1 | grep -qF '"abi":{"ran":true,"structs":3'; then
    note "Fase 5 abi: check --abi masuk JSON summary"
else
    fail "Fase 5 abi: check --abi tidak masuk JSON summary"
fi
# Exit criteria SOL-14: ABI drift ditolak dalam transaction.
gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/abi_tx_reject test/abi_tx_reject.c myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c prove.c filc.c driver.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c > /dev/null 2>&1
if ./test/abi_tx_reject > /dev/null 2>&1; then
    note "Fase 5 abi: ABI drift ditolak dalam transaction (exit criteria)"
else
    fail "Fase 5 abi: transaction tidak menolak ABI drift"
fi
rm -f test/abi_tx_reject

# --- 6j. Fase 5 (SOL-12): Resource Linearity Ledger (//@ resource) ---
# Fixture bersih: 2 acquire-release seimbang (nested oblique diabaikan).
if ./myc resource test/fixtures/resource_clean.c 2>&1 | grep -qF "2 acquire, 2 release"; then
    note "Fase 5 resource: fixture bersih seimbang (acquire=2 release=2)"
else
    fail "Fase 5 resource: fixture bersih tidak seimbang"
fi
if ./myc resource test/fixtures/resource_clean.c 2>&1 | grep -qF "0 leak, 0 double, 0 unknown"; then
    note "Fase 5 resource: fixture bersih = 0 temuan (clean)"
else
    fail "Fase 5 resource: fixture bersih memunculkan temuan"
fi
# Fixture leak: fopen tanpa fclose => 1 leak, witness acq..end.
if ./myc resource test/fixtures/resource_leak.c 2>&1 | grep -qF "1 leak"; then
    note "Fase 5 resource: leak terdeteksi (fopen tanpa fclose)"
else
    fail "Fase 5 resource: leak tidak terdeteksi"
fi
if ./myc resource test/fixtures/resource_leak.c 2>&1 | grep -qF "witness: acq@11..end@15"; then
    note "Fase 5 resource: witness jalur acq..end benar"
else
    fail "Fase 5 resource: witness acq..end salah"
fi
# Fixture double-release: fclose dua kali => 1 double.
if ./myc resource test/fixtures/resource_double.c 2>&1 | grep -qF "1 double"; then
    note "Fase 5 resource: double-release terdeteksi"
else
    fail "Fase 5 resource: double-release tidak terdeteksi"
fi
# Fixture transfer: return var => 1 transfer, bukan leak.
if ./myc resource test/fixtures/resource_transfer.c 2>&1 | grep -qF "transfer=1"; then
    note "Fase 5 resource: resource ditransfer (return var) bukan leak"
else
    fail "Fase 5 resource: resource transfer tidak dikenali"
fi
# Resource non-blocking: verdict tetap OK kendati ada temuan ledger.
if ./myc check test/fixtures/resource_leak.c --no-cache --json-summary 2>&1 | grep -qF '"verdict":"OK"'; then
    note "Fase 5 resource: temuan ledger TIDAK menurunkan verdict (NON-blocking)"
else
    fail "Fase 5 resource: verdict berubah oleh observasi ledger"
fi
# Resource masuk JSON summary.
if ./myc check test/fixtures/resource_leak.c --no-cache --json-summary 2>&1 | grep -qF '"resource":{"ran":true'; then
    note "Fase 5 resource: resource masuk JSON summary"
else
    fail "Fase 5 resource: tidak masuk JSON summary"
fi

# --- 6k. Fase 5 (SOL-11): Units / Shape / Provenance Contracts ---
# Fixture bersih: annotation konsisten => 0 temuan.
if ./myc units test/fixtures/units_clean.c 2>&1 | grep -qF "0 unbound, 0 unit-mismatch, 0 shape-dim, 0 dup-conflict"; then
    note "Fase 5 units: fixture bersih = 0 temuan (clean)"
else
    fail "Fase 5 units: fixture bersih memunculkan temuan"
fi
# Fixture rusak: unbound identifier terdeteksi (data_len tak ada di kode).
if ./myc units test/fixtures/units_broken.c 2>&1 | grep -qF "1 unbound"; then
    note "Fase 5 units: identifier annotation tak terikat (unbound) terdeteksi"
else
    fail "Fase 5 units: unbound tidak terdeteksi"
fi
# Unit mismatch pada assignment (count(elements) = raw_len(bytes)).
if ./myc units test/fixtures/units_broken.c 2>&1 | grep -qF "1 unit-mismatch"; then
    note "Fase 5 units: unit mismatch pada assignment terdeteksi"
else
    fail "Fase 5 units: unit mismatch tidak terdeteksi"
fi
# Shape-dim: capacity vs length beda unit (bytes vs elements).
if ./myc units test/fixtures/units_broken.c 2>&1 | grep -qF "2 shape-dim"; then
    note "Fase 5 units: shape_dim capacity vs length terdeteksi"
else
    fail "Fase 5 units: shape_dim tidak terdeteksi"
fi
# Dup: unit count elements lalu bytes + endian little lalu big.
if ./myc units test/fixtures/units_broken.c 2>&1 | grep -qF "2 dup-conflict"; then
    note "Fase 5 units: konflik annotation ganda (dup) terdeteksi"
else
    fail "Fase 5 units: dup tidak terdeteksi"
fi
# Units non-blocking: verdict tetap OK walau ada temuan unit.
if ./myc check test/fixtures/units_broken.c --no-cache --json-summary 2>&1 | grep -qF '"verdict":"OK"'; then
    note "Fase 5 units: temuan unit TIDAK menurunkan verdict (NON-blocking)"
else
    fail "Fase 5 units: verdict berubah oleh observasi unit"
fi
# Units masuk JSON summary.
if ./myc check test/fixtures/units_clean.c --no-cache --json-summary 2>&1 | grep -qF '"units":{"ran":true'; then
    note "Fase 5 units: units masuk JSON summary"
else
    fail "Fase 5 units: tidak masuk JSON summary"
fi

# --- 6l. Fase 7 (SOL-20): Model/Harness Error Fingerprint ---
# Opt-in: tanpa --profile / env, TIDAK ada file profil dibuat.
rm -rf .myc/profiles
./myc check test/fixtures/units_clean.c --no-cache > /dev/null 2>&1
if [ ! -d .myc/profiles ] || [ -z "$(ls -A .myc/profiles 2>/dev/null)" ]; then
    note "Fase 7 profile: tanpa opt-in, tidak ada profil dibuat"
else
    fail "Fase 7 profile: profil dibuat tanpa opt-in"
fi
# Opt-in: check dengan --profile membuat agregat + tercatat di list.
rm -rf .myc/profiles
./myc check test/fixtures/units_clean.c --no-cache --profile ci-harness > /dev/null 2>&1
if ./myc profile show ci-harness 2>&1 | grep -qF "id      : ci-harness"; then
    note "Fase 7 profile: profil tercatat via --profile"
else
    fail "Fase 7 profile: profil tidak tercatat"
fi
# env MYC_PROFILE_ID juga opt-in (tanpa flag).
rm -rf .myc/profiles
MYC_PROFILE_ID=ci-env ./myc check test/fixtures/units_clean.c --no-cache > /dev/null 2>&1
if ./myc profile show ci-env 2>&1 | grep -qF "checks  : 1"; then
    note "Fase 7 profile: env MYC_PROFILE_ID dihormati"
else
    fail "Fase 7 profile: env tidak dihormati"
fi
# Agregasi: 2 check => checks=2 (cache-hit pun dihitung = permintaan check).
./myc check test/fixtures/units_clean.c --no-cache --profile ci-harness > /dev/null 2>&1
./myc check test/fixtures/units_clean.c --no-cache --profile ci-harness > /dev/null 2>&1
if ./myc profile show ci-harness 2>&1 | grep -qF "checks  : 2"; then
    note "Fase 7 profile: agregasi antar check bekerja"
else
    fail "Fase 7 profile: agregasi tidak bekerja"
fi
# NON-blocking: profil tidak mengubah verdict / exit code.
rm -rf .myc/profiles
V1=$(./myc check test/fixtures/units_broken.c --no-cache --json-summary 2>&1)
V2=$(./myc check test/fixtures/units_broken.c --no-cache --profile ci-harness --json-summary 2>&1)
echo "$V1" | grep -qF '"verdict":"OK"' && echo "$V2" | grep -qF '"verdict":"OK"' \
    && note "Fase 7 profile: profile NON-blocking (verdict tetap)" \
    || fail "Fase 7 profile: profil mengubah verdict"
# --profile id invalid = fail-fast exit 2.
if ./myc check test/fixtures/units_clean.c --no-cache --profile 'bad id' > /dev/null 2>&1; then
    fail "Fase 7 profile: id invalid tidak fail-fast"
else
    note "Fase 7 profile: id invalid ditolak (exit != 0)"
fi
# myc profile reset menghapus profil.
if ./myc profile reset ci-harness 2>&1 | grep -qF "direset" && \
   ! ./myc profile show ci-harness > /dev/null 2>&1; then
    note "Fase 7 profile: reset menghapus profil"
else
    fail "Fase 7 profile: reset tidak bekerja"
fi
rm -rf .myc/profiles

# --- 6m. Fase 7 (SOL-21): Trust Calibration Ledger (myc calibrate) ---
# Opt-in per local ledger (.myc/calibration.json). Bukan hard gate; hanya anotasi
# observasi diagnostic LOW/DISABLED (trust rule 1-3: verdict TIDAK berubah).
rm -f .myc/calibration.json
# Derived state: 3x accepted -> OK; 3x rejected -> DISABLED;
# 1 accepted + 2 rejected -> LOW (score=-2, total>=3).
./myc calibrate mark c_ok accepted --match "ok_marker" > /dev/null 2>&1
./myc calibrate mark c_ok accepted --match "ok_marker" > /dev/null 2>&1
./myc calibrate mark c_ok accepted --match "ok_marker" > /dev/null 2>&1
./myc calibrate show c_ok 2>&1 | grep -qF "state     : OK" && note "Fase 7 calibrate: 3x accepted -> OK" || fail "Fase 7 calibrate: state OK gagal"
./myc calibrate mark c_dis rejected --match "dis_marker" > /dev/null 2>&1
./myc calibrate mark c_dis rejected --match "dis_marker" > /dev/null 2>&1
./myc calibrate mark c_dis rejected --match "dis_marker" > /dev/null 2>&1
./myc calibrate show c_dis 2>&1 | grep -qF "state     : DISABLED" && note "Fase 7 calibrate: 3x rejected -> DISABLED" || fail "Fase 7 calibrate: state DISABLED gagal"
./myc calibrate mark c_low accepted --match "low_marker" > /dev/null 2>&1
./myc calibrate mark c_low rejected --match "low_marker" > /dev/null 2>&1
./myc calibrate mark c_low rejected --match "low_marker" > /dev/null 2>&1
./myc calibrate show c_low 2>&1 | grep -qF "state     : LOW" && note "Fase 7 calibrate: 1a+2r -> LOW" || fail "Fase 7 calibrate: state LOW gagal"
# list + reset.
./myc calibrate list 2>&1 | grep -qF "c_ok" && note "Fase 7 calibrate: list menampilkan rule" || fail "Fase 7 calibrate: list tidak menampilkan rule"
./myc calibrate reset c_ok > /dev/null 2>&1
if ! ./myc calibrate show c_ok > /dev/null 2>&1; then
    note "Fase 7 calibrate: reset menghapus rule (tidak ditemukan setelah reset)"
else
    fail "Fase 7 calibrate: reset tidak menghapus rule"
fi
# id invalid = fail-fast (exit != 0).
if ./myc calibrate mark 'bad id' accepted > /dev/null 2>&1; then
    fail "Fase 7 calibrate: id invalid tidak fail-fast"
else
    note "Fase 7 calibrate: id invalid ditolak (exit != 0)"
fi
# Exit criteria SOL-21: rule DISABLED tidak menghasilkan hard finding.
# Fixture mmio_bad.c --freestanding: observasi C3 non-blocking; --calibrate
# menanamkan "[calibrated: DISABLED]" pada match dan verdict tetap OK.
./myc calibrate mark c_mmio rejected --match "MMIO deref alamat absolut tanpa volatile" > /dev/null 2>&1
./myc calibrate mark c_mmio rejected --match "MMIO deref alamat absolut tanpa volatile" > /dev/null 2>&1
./myc calibrate mark c_mmio rejected --match "MMIO deref alamat absolut tanpa volatile" > /dev/null 2>&1
if ./myc check test/fixtures/mmio_bad.c --freestanding --calibrate --no-cache 2>&1 | grep -qF '[calibrated: DISABLED] rule=c_mmio'; then
    note "Fase 7 calibrate: DISABLED rule dianotasi di report"
else
    fail "Fase 7 calibrate: anotasi DISABLED hilang"
fi
if ./myc check test/fixtures/mmio_bad.c --freestanding --calibrate --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "Fase 7 calibrate: DISABLED rule tidak menghasilkan hard finding (exit criteria)"
else
    fail "Fase 7 calibrate: DISABLED rule turunkan verdict"
fi
# NON-blocking: --calibrate tidak mengubah verdict source bersih.
if ./myc check tests/ok_hello.c --calibrate --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "Fase 7 calibrate: --calibrate NON-blocking (ok_hello tetap OK)"
else
    fail "Fase 7 calibrate: --calibrate mengubah verdict"
fi
rm -f .myc/calibration.json
rm -rf .myc/profiles

# --- 6o. Fase 7 (#2029, DS-14): Expected-Information-Gain scheduler (myc eig) ---
# Rekomendasi eksperimen terurut skor expected_value = P(new_evidence) x
# severity x scope / (time x token); prior tabel deterministik yang
# dikalibrasi dari ledger SOL-21 (rule `eig-<slug>`) + profil SOL-20.
# NON-blocking: verdict tidak pernah berubah.
rm -f .myc/calibration.json
rm -rf .myc/profiles
if ./myc eig test/fixtures/eig_clean.c 2>&1 | grep -qF "eig scheduler (Fase 7, DS-14)"; then
    note "Fase 7 eig: laporan scheduler tercetak"
else
    fail "Fase 7 eig: laporan scheduler tidak tercetak"
fi
if ./myc eig test/fixtures/eig_clean.c 2>&1 | grep -qF "rekomendasi: 6"; then
    note "Fase 7 eig: 6 rekomendasi dari 6 hazard untested"
else
    fail "Fase 7 eig: jumlah rekomendasi bukan 6"
fi
if ./myc eig test/fixtures/eig_clean.c 2>&1 | grep -qF "expected-value="; then
    note "Fase 7 eig: expected-value tercetak per rekomendasi"
else
    fail "Fase 7 eig: expected-value tidak tercetak"
fi
# --unchanged: prior dibagi dua (informasi baru kecil kemungkinannya).
if ./myc eig test/fixtures/eig_clean.c --unchanged 2>&1 | grep -qF "source_changed: 0"; then
    note "Fase 7 eig: --unchanged dicerminkan (source_changed: 0)"
else
    fail "Fase 7 eig: --unchanged tidak dicerminkan"
fi
# --budget-ms 100: semua eksperimen (cost >= 1500ms) di luar budget.
if ./myc eig test/fixtures/eig_clean.c --budget-ms 100 2>&1 | grep -qF "within_budget: 0/"; then
    note "Fase 7 eig: budget 100ms -> semua rekomendasi di luar budget"
else
    fail "Fase 7 eig: budget 100ms tidak menghasilkan within_budget 0"
fi
# Kalibrasi ledger (SOL-21): 3x accepted rule `eig-runtime-memory-asan-ubsan`
# (hazard "runtime memory (ASan/UBSan)", eligible untested) -> prior naik.
./myc calibrate mark eig-runtime-memory-asan-ubsan accepted --match "eig_test" > /dev/null 2>&1
./myc calibrate mark eig-runtime-memory-asan-ubsan accepted --match "eig_test" > /dev/null 2>&1
./myc calibrate mark eig-runtime-memory-asan-ubsan accepted --match "eig_test" > /dev/null 2>&1
if ./myc eig test/fixtures/eig_clean.c 2>&1 | grep -qF "calibrated_rules: 1"; then
    note "Fase 7 eig: kalibrasi ledger SOL-21 terbaca (calibrated_rules: 1)"
else
    fail "Fase 7 eig: kalibrasi ledger SOL-21 tidak terbaca"
fi
./myc calibrate reset eig-runtime-memory-asan-ubsan > /dev/null 2>&1
# Profil SOL-20 (opt-in): prior disesuaikan kelas gate historis harness.
./myc check test/fixtures/eig_clean.c --no-cache --profile ci-eig > /dev/null 2>&1
if ./myc eig test/fixtures/eig_clean.c --profile ci-eig 2>&1 | grep -qF "profile: ci-eig"; then
    note "Fase 7 eig: profil SOL-20 dibaca (profile: ci-eig)"
else
    fail "Fase 7 eig: profil SOL-20 tidak dibaca"
fi
# --json deterministik (expected_value per rekomendasi).
if ./myc eig test/fixtures/eig_clean.c --json 2>&1 | grep -qF '"expected_value"'; then
    note "Fase 7 eig: output --json memuat expected_value"
else
    fail "Fase 7 eig: output --json tidak memuat expected_value"
fi
# NON-blocking: eig tidak pernah mengubah verdict check.
if ./myc check test/fixtures/eig_clean.c --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "Fase 7 eig: NON-blocking (verdict tetap OK)"
else
    fail "Fase 7 eig: verdict berubah oleh eig"
fi
rm -f .myc/calibration.json
rm -rf .myc/profiles

# --- 6p. Fase 7 (SOL-10): Candidate Tournament dengan Pareto Frontier ---
# `myc compare-candidates <base.c> <c1.c> [c2.c ...]`: menilai kandidat
# patch pada dimensi terukur deterministik (hard_gate/findings/
# obligations_lost/churn/verification_cost/runtime_proxy/portability/
# readability; stack_impact = UNMEASURED v1, gap terlihat). Pareto
# frontier = TIDAK didominasi pada dimensi yang terukur (anti-overclaim
# SOL-10: bukan "terbaik umum"). NON-blocking: exit 0.
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c > /dev/null 2>&1; then
    note "Fase 7 cand: tournament NON-blocking (exit 0)"
else
    fail "Fase 7 cand: exit bukan 0"
fi
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "candidate tournament (Fase 7, SOL-10)"; then
    note "Fase 7 cand: laporan tournament tercetak"
else
    fail "Fase 7 cand: laporan tournament tidak tercetak"
fi
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "2 kandidat vs baseline"; then
    note "Fase 7 cand: 2 kandidat vs baseline"
else
    fail "Fase 7 cand: jumlah kandidat salah"
fi
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "dimensi terukur: 8 dari 9"; then
    note "Fase 7 cand: 8 dari 9 dimensi terukur"
else
    fail "Fase 7 cand: jumlah dimensi terukur salah"
fi
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "stack_impact = UNMEASURED"; then
    note "Fase 7 cand: gap stack_impact UNMEASURED terlihat (bukan kesunyian)"
else
    fail "Fase 7 cand: gap stack_impact tidak terlihat"
fi
# cand_better (fix lint baseline): findings 0 + kontrak requires dipertahankan.
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "findings=0 obligations_lost=0 churn=14"; then
    note "Fase 7 cand: cand_better findings 0 + kontrak dipertahankan"
else
    fail "Fase 7 cand: dimensi cand_better tidak sesuai"
fi
# cand_worse (regresi): findings 2 + obligations_lost 1 (kontrak dibuang).
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "findings=2 obligations_lost=1 churn=24"; then
    note "Fase 7 cand: cand_worse findings 2 + obligations_lost 1"
else
    fail "Fase 7 cand: dimensi cand_worse tidak sesuai"
fi
# Pareto: cand_worse didominasi (oleh baseline, index terkecil menang).
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c 2>&1 | grep -qF "didominasi oleh: test/fixtures/cand_base.c"; then
    note "Fase 7 cand: cand_worse didominasi oleh baseline"
else
    fail "Fase 7 cand: dominator cand_worse bukan baseline"
fi
# --json: schema myc.candidate.v1 deterministik.
if ./myc compare-candidates test/fixtures/cand_base.c test/fixtures/cand_better.c test/fixtures/cand_worse.c --json 2>&1 | grep -qF '"schema":"myc.candidate.v1"'; then
    note "Fase 7 cand: output --json memuat schema myc.candidate.v1"
else
    fail "Fase 7 cand: output --json tidak memuat schema"
fi
# Baseline tidak terbaca -> fail-fast exit 2 (bukan NON-blocking).
if ./myc compare-candidates test/fixtures/tidak-ada.c test/fixtures/cand_better.c > /dev/null 2>&1; then
    fail "Fase 7 cand: baseline hilang harus exit != 0"
else
    note "Fase 7 cand: baseline hilang -> fail-fast exit 2"
fi

# --- 6r. Fase 7 (Privacy/size controls): --agent-payload-cap + --no-persist ---
# `--agent-payload-cap BYTES`: override cap payload --agent (0 = default
# MYC_AGENT_PAYLOAD_CAP 16384; valid 1024..1048576; invalid = fail-fast
# exit 2, pola MYC-AUDIT-019/020). `--no-persist`: mode privasi tanpa
# jejak disk -- ledger/cache/asumsi/profil TIDAK ditulis, verdict/hasil
# run TIDAK berubah (NON-blocking penuh). Kontradiksi dgn --profile =
# fail-fast (pola A1: --no-assumptions + --require-assumptions-closed).
if ./myc check tests/ok_hello.c --agent --agent-payload-cap 4096 --no-cache 2>&1 | grep -qF 'payload_cap":4096'; then
    note "Fase 7 priv: --agent-payload-cap 4096 diterapkan"
else
    fail "Fase 7 priv: cap 4096 tidak ter-reflect di agent JSON"
fi
if ./myc check tests/ok_hello.c --agent --no-cache 2>&1 | grep -qF 'payload_cap":16384'; then
    note "Fase 7 priv: default cap 16384 (tanpa flag)"
else
    fail "Fase 7 priv: default cap bukan 16384"
fi
# fail-fast: non-angka + di luar rentang valid.
if ./myc check tests/ok_hello.c --agent-payload-cap abc > /dev/null 2>&1; then
    fail "Fase 7 priv: cap non-angka harus exit 2"
else
    note "Fase 7 priv: cap non-angka fail-fast exit 2"
fi
if ./myc check tests/ok_hello.c --agent-payload-cap 100 > /dev/null 2>&1; then
    fail "Fase 7 priv: cap di bawah min harus exit 2"
else
    note "Fase 7 priv: cap 100 (di bawah min 1024) fail-fast exit 2"
fi
# --no-persist: ledger TIDAK ditulis + verdict tetap OK (NON-blocking).
rm -f .myc/ledger.json
if ./myc check tests/ok_hello.c --no-persist --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    if [ -f .myc/ledger.json ]; then
        fail "Fase 7 priv: --no-persist tetap menulis ledger"
    else
        note "Fase 7 priv: --no-persist tanpa jejak ledger + verdict OK"
    fi
else
    fail "Fase 7 priv: verdict --no-persist bukan OK"
fi
rm -f .myc/ledger.json
# --no-persist + --profile = kontradiksi (pola A1).
if ./myc check tests/ok_hello.c --no-persist --profile xyz > /dev/null 2>&1; then
    fail "Fase 7 priv: --no-persist + --profile harus exit 2"
else
    note "Fase 7 priv: --no-persist + --profile kontradiksi fail-fast"
fi

# --- 6s. Fase 7 (Project-local prompt/spec pack): myc prompt + pack ---
# `myc prompt <file.c>` (D4/DS-15) diperkaya pack proyek lokal:
# myc.prompt.md (teks bebas) + myc.spec.json (spec terstruktur) di
# direktori proyek (--pack-dir DIR; default cwd). NON-blocking penuh
# (verdict TIDAK pernah berubah); --no-pack mematikan; spec.json ADA
# tapi invalid = fail-fast exit 2 (pola scenario).
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack 2>&1 | grep -qF 'PACK-MARKER'; then
    note "Fase 7 pack: prompt.md disisipkan verbatim"
else
    fail "Fase 7 pack: PACK-MARKER dari myc.prompt.md tidak muncul"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack 2>&1 | grep -qF 'pack-fixture'; then
    note "Fase 7 pack: spec name dari myc.spec.json tampil"
else
    fail "Fase 7 pack: spec name pack-fixture tidak muncul"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack 2>&1 | grep -qF 'MYC_BUF'; then
    note "Fase 7 pack: rule dari spec.json tampil"
else
    fail "Fase 7 pack: rule MYC_BUF dari spec.json tidak muncul"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack 2>&1 | grep -qF 'gets'; then
    note "Fase 7 pack: deny_functions dari spec.json tampil"
else
    fail "Fase 7 pack: deny_functions gets tidak muncul"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack 2>&1 | grep -q 'sha256'; then
    note "Fase 7 pack: sha256 pack dilaporkan (deterministik)"
else
    fail "Fase 7 pack: sha256 tidak ada di output"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack --no-pack 2>&1 | grep -qF 'PACK-MARKER'; then
    fail "Fase 7 pack: --no-pack harus menonaktifkan pack"
else
    note "Fase 7 pack: --no-pack menonaktifkan pack"
fi
if ./myc prompt tests/ok_hello.c --pack-dir test/fixtures/pack_bad > /dev/null 2>&1; then
    fail "Fase 7 pack: spec.json invalid harus exit 2"
else
    note "Fase 7 pack: spec.json invalid fail-fast exit 2"
fi
if ./myc check tests/ok_hello.c --no-cache 2>&1 | grep -qF "verdict:   OK"; then
    note "Fase 7 pack: verdict check tidak berubah (NON-blocking)"
else
    fail "Fase 7 pack: verdict check berubah oleh pack"
fi

# --- 6t. Fase 7 (pack wiring): pack masuk output --agent + context SOL-22 ---
# Pack proyek lokal (myc.prompt.md + myc.spec.json) kini di-wire ke
# `myc check --agent` (objek "pack" di agent JSON) dan `myc context`
# (section "project pack", prioritas terendah). NON-blocking penuh.
if ./myc check tests/ok_hello.c --agent --pack-dir test/fixtures/pack --no-cache 2>&1 | grep -qF 'prompt_present'; then
    note "Fase 7 pack-wire: objek pack ada di agent JSON (--agent)"
else
    fail "Fase 7 pack-wire: objek pack hilang dari agent JSON"
fi
if ./myc check tests/ok_hello.c --agent --pack-dir test/fixtures/pack --no-cache 2>&1 | grep -qF 'pack-fixture'; then
    note "Fase 7 pack-wire: isi prompt.md + spec terserialisasi (marker)"
else
    fail "Fase 7 pack-wire: isi pack tidak terserialisasi di agent JSON"
fi
if ./myc check tests/ok_hello.c --agent --pack-dir test/fixtures/pack --no-pack --no-cache 2>&1 | grep -qF 'prompt_present'; then
    fail "Fase 7 pack-wire: --no-pack masih menyertakan pack di agent"
else
    note "Fase 7 pack-wire: --no-pack menonaktifkan pack di agent"
fi
if ./myc check tests/ok_hello.c --agent --pack-dir test/fixtures/pack_bad --no-cache > /dev/null 2>&1; then
    fail "Fase 7 pack-wire: spec.json invalid harus exit 2 di --agent"
else
    note "Fase 7 pack-wire: spec invalid fail-fast exit 2 di --agent"
fi
if ./myc context tests/ok_hello.c --pack-dir test/fixtures/pack --no-cache 2>&1 | grep -qF '## project pack'; then
    note "Fase 7 pack-wire: section project pack ada di context (SOL-22)"
else
    fail "Fase 7 pack-wire: section project pack hilang dari context"
fi
if ./myc context tests/ok_hello.c --pack-dir test/fixtures/pack --no-pack --no-cache 2>&1 | grep -qF 'tidak ada pack proyek'; then
    note "Fase 7 pack-wire: context --no-pack menandai pack absen eksplisit"
else
    fail "Fase 7 pack-wire: context --no-pack tidak menandai pack absen"
fi
if ./myc check tests/ok_hello.c --agent --pack-dir test/fixtures/pack --no-cache 2>&1 | grep -qF '"verdict":0'; then
    note "Fase 7 pack-wire: verdict agent tetap OK (NON-blocking)"
else
    fail "Fase 7 pack-wire: verdict agent berubah oleh pack"
fi
# Enforcement --agent-payload-cap: pack = enrichment yang dibuang
# TERAKHIR. Cap 1300 pada file ber-finding -> pack dibuang tapi
# protokol inti (verdict) tetap utuh.
if ./myc check test/fixtures/blinky_bad.c --agent --pack-dir test/fixtures/pack --agent-payload-cap 1300 --no-cache 2>&1 | grep -qF 'prompt_present'; then
    fail "Fase 7 pack-wire: pack harus dibuang saat cap ketat (enrichment terakhir)"
else
    note "Fase 7 pack-wire: pack dibuang saat cap ketat"
fi
if ./myc check test/fixtures/blinky_bad.c --agent --pack-dir test/fixtures/pack --agent-payload-cap 1300 --no-cache 2>&1 | grep -qF '"verdict":0'; then
    note "Fase 7 pack-wire: verdict tetap OK saat pack dibuang (protokol inti utuh)"
else
    fail "Fase 7 pack-wire: verdict hilang saat pack dibuang"
fi

# --- 7a. Fase 0 Golden Schema + Malformed-Input (myc.result.v1) ---
if bash test/_schema_golden.sh; then
    note "Fase 0 golden schema: 13 cek PASS (schema + malformed input)"
else
    fail "Fase 0 golden schema: ada cek GAGAL"
fi

# --- 7b. Fase -1 Baseline Benchmark (20 task, SOL-24) ---
if bash bench/run_bench.sh > /tmp/bench_ci.log 2>&1; then
    note "Fase -1 benchmark: 20 task PASS (baseline tersimpan di bench/reports/)"
else
    grep -E '\[FAIL\]|BENCHMARK' /tmp/bench_ci.log | head -8
    fail "Fase -1 benchmark: ada task GAGAL (detection/precision baseline)"
fi

# --- 8. audit018 (deadlock/OOM/concurrency/fork/descendants) ---
if bash test/_audit018.sh; then
    note "audit018 SELESAI OK"
else
    fail "audit018"
fi

# --- 8a. Fase 8 Release Gate: anti-false-OK guard (MYC-AUDIT-031, POSIX) ---
if bash test/_anti_false_ok.sh; then
    note "Fase 8 anti-false-OK: fixture negatif tetap negatif (tidak false-OK)"
else
    fail "Fase 8 anti-false-OK: ada fixture negatif yang jadi OK"
fi

# --- 8b. Fase 8 Release Gate: no-source-leak (DoD privacy) ---
if bash test/_no_source_leak.sh; then
    note "Fase 8 no-source-leak: source tidak bocor ke payload/report (hanya hash)"
else
    fail "Fase 8 no-source-leak: source verbatim bocor ke output"
fi

echo "=== _ci_linux.sh: PASS=$PASS FAIL=$FAIL ==="
exit $FAIL
