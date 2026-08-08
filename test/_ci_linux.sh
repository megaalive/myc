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
         agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c; do
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
if ./myc compare test/fixtures/ref_crc16.c test/fixtures/new_crc16_div.c 2>&1 | grep -qF "divergen 53 kasus"; then
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
if ./myc check tests/ok_hello.c --stack-budget 10 --no-cache 2>&1 | grep -qF "480%"; then
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
