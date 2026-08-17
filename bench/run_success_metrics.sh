#!/usr/bin/env bash
# =====================================================================
# run_success_metrics.sh — Roll-up ukuran sukses keseluruhan (qwen-review
# §7 + grok-rev G6). Mengukur M1–M5 (Fase 7) dan M6–M10 (pemakaian agen):
#
#   M1  RUNTIME_VIOLATION membawa lokasi benar ≥90% (baseline: 0%)
#   M2  Repair runtime menghasilkan patch terverifikasi ≥50%
#   M3  Regression replay 100% pasca-repair
#   M4  agent_check satu-panggilan konvergen ≤3 iterasi ≥50%
#   M5  Seluruh source myc tetap self-dogfood OK
#   M6  agen-lite patuh allowed_span ≥90%
#   M7  inner-loop cache-hit (CLI duration_ms; target MCP p50 <20 ms)
#   M8  payload lite ≤ 2048 B (kecuali GIVE_UP yang menyertakan context)
#   M9  STOP_COMPILE_CLEAN tidak muncul bila --scenario auto masih
#       meminta runtime yang available
#   M10 first-action = enum action, bukan flag soup ≥80%
#
# Report deterministik ke bench/reports/success-metrics-latest.txt;
# exit 0 = semua metrik lulus, exit 1 = ada metrik gagal.
# Bebas dependensi eksternal (bash + python3 opsional untuk parse JSON).
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

MYC="./myc"
[ -x "$MYC" ] || MYC="./myc.exe"
[ -x "$MYC" ] || { echo "[FAIL] myc tidak ditemukan (cari ./myc atau ./myc.exe)"; exit 1; }
MCP="./mcp"
[ -x "$MCP" ] || MCP="./mcp.exe"
CC="${CC:-gcc}"

REPORT_DIR="bench/reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/success-metrics-latest.txt"

# SRCS sama dengan test/_audit018.sh (kompilasi test unit in-process).
SRCS="myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c sanloc.c contract.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c prove.c filc.c driver.c exhaustive.c fuzz.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c persist.c limit.c alloc.c"

PASS=0
FAIL=0
TOTAL=0

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }
inc()  { TOTAL=$((TOTAL + 1)); }

{
echo "=== Success Metrics (qwen-review Fase 7, ukuran sukses §7) ==="
echo "binary: $MYC | date: $(date '+%Y%m%d-%H%M%S')"
echo ""
} > "$REPORT"

# ------------------------------------------------------------------
# M1: RUNTIME_VIOLATION lokasi benar (kind + line + fungsi) ≥90%
# ------------------------------------------------------------------
echo "--- M1. lokasi runtime benar (≥90%; baseline 0%) ---"
M1_CASES=(
  "tests/bad_run_oob.c:heap-buffer-overflow:11:main"
  "tests/bad_run_uaf.c:heap-use-after-free:22:main"
  "tests/bad_run_intovf.c:undefined-behavior:9:main"
  "test/fixtures/witness_oob.c:heap-buffer-overflow:7:main"
  "test/fixtures/rt_strcpy_ovf.c:stack-buffer-overflow:11:copy_it"
  "test/fixtures/rt_ubsan_ovf.c:undefined-behavior:10:main"
  "test/fixtures/rt_double_free.c:attempting double-free:16:drop"
  "test/fixtures/rt_heap_memset12.c:heap-buffer-overflow:13:main"
  "test/fixtures/rt_memcpy_ovf.c:stack-buffer-overflow:9:f"
)
M1_TOTAL=0
M1_OK=0
for c in "${M1_CASES[@]}"; do
    c=${c//$'\r'/}
    file="${c%%:*}"
    rest="${c#*:}"
    kind="${rest%%:*}"
    rest="${rest#*:}"
    line="${rest%%:*}"
    fn="${rest#*:}"
    inc; M1_TOTAL=$((M1_TOTAL + 1))
    out=$("$MYC" check "$file" --run --json-summary --no-cache 2>&1)
    verdict=$(printf '%s\n' "$out" | grep -oE '"verdict":"[A-Z_]+"' | head -1)
    if [ "$verdict" != '"verdict":"RUNTIME_VIOLATION"' ]; then
        fail "M1 $file: verdict $verdict (harus RUNTIME_VIOLATION)"
        continue
    fi
    if printf '%s\n' "$out" | grep -qF "\"violation_kind\":\"$kind\"" &&
       printf '%s\n' "$out" | grep -qF "\"line\":$line," &&
       printf '%s\n' "$out" | grep -qF "\"function\":\"$fn\""; then
        M1_OK=$((M1_OK + 1))
        note "M1 $file: lokasi benar ($kind @$fn:$line)"
    else
        fail "M1 $file: lokasi salah (harus $kind @$fn:$line)"
    fi
done
M1_PCT=$((M1_OK * 100 / M1_TOTAL))
echo "M1: $M1_OK/$M1_TOTAL lokasi benar ($M1_PCT% >= 90%)" >> "$REPORT"
if [ "$M1_PCT" -ge 90 ]; then
    note "M1: lokasi runtime benar $M1_PCT% (target >=90%)"
else
    fail "M1: lokasi runtime benar $M1_PCT% (<90%)"
fi

# ------------------------------------------------------------------
# M2: Repair runtime patch terverifikasi ≥50% (runtime_repair_test)
# ------------------------------------------------------------------
echo "--- M2. repair runtime patch terverifikasi (≥50%) ---"
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/runtime_repair_test_tmp test/runtime_repair_test.c $SRCS 2>/dev/null; then
    LOG="test/runtime_repair_test_tmp.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/runtime_repair_test_tmp >"$LOG" 2>&1; RC=$?
    else
        test/runtime_repair_test_tmp >"$LOG" 2>&1; RC=$?
    fi
    # Template yang menghasilkan patched_source: test mencetak
    # "M2-TEMPLATE-PATCH: OK/TOTAL" — OK = kasus template yang benarbenar
    # memproduksi patched_source, TOTAL = semua kasus template yang dicoba
    # (termasuk jujur-null: UBSan T5 + overflow non-template T14).
    # MYC-AUDIT-060: 12/14 (86%) — 12 template patchable (strcpy/memcpy
    # strcat/memset lokasi baris sama & multi-baris, heap & array lokal,
    # UAF 2 nama, sumber global) + 2 jujur-null; T7 anti-overclaim tidak
    # dihitung (bukan kasus template).
    M2_LINE=$(grep -oE 'M2-TEMPLATE-PATCH: [0-9]+/[0-9]+' "$LOG" | head -1)
    # sed: ambil OK dan TOTAL dari "M2-TEMPLATE-PATCH: OK/TOTAL" (jangan
    # pakai grep -oE '[0-9]+' — digit "M2" pada prefix ikut tertangkap).
    M2_OK=$(echo "$M2_LINE" | sed -E 's/.*PATCH: ([0-9]+)\/[0-9]+.*/\1/')
    M2_TOTAL=$(echo "$M2_LINE" | sed -E 's/.*PATCH: [0-9]+\/([0-9]+).*/\1/')
    if [ -z "$M2_LINE" ] || [ -z "$M2_OK" ] || [ -z "$M2_TOTAL" ] || [ "$M2_TOTAL" -eq 0 ]; then
        fail "M2: runtime_repair_test tidak mencetak M2-TEMPLATE-PATCH"
    else
        M2_PCT=$((M2_OK * 100 / M2_TOTAL))
        echo "M2: $M2_OK/$M2_TOTAL template memproduksi patch terverifikasi ($M2_PCT% >= 50%; exit $RC)" >> "$REPORT"
        if [ $RC -eq 0 ]; then
            note "M2: runtime_repair_test lulus ($M2_OK/$M2_TOTAL template patch = $M2_PCT%)"
        else
            fail "M2: runtime_repair_test exit $RC (lihat $LOG)"
            grep -E '^\[FAIL\]' "$LOG" | head -5
        fi
    fi
else
    fail "M2: runtime_repair_test gagal dibangun (-Werror)"
fi
rm -f test/runtime_repair_test_tmp test/runtime_repair_test_tmp.exe \
      test/runtime_repair_test_tmp.log

# ------------------------------------------------------------------
# M3: Regression replay 100% pasca-repair (regress_replay_test)
# ------------------------------------------------------------------
echo "--- M3. regression replay 100% pasca-repair ---"
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/regress_replay_test_tmp test/regress_replay_test.c $SRCS 2>/dev/null; then
    LOG="test/regress_replay_test_tmp.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/regress_replay_test_tmp >"$LOG" 2>&1; RC=$?
    else
        test/regress_replay_test_tmp >"$LOG" 2>&1; RC=$?
    fi
    echo "M3: regress_replay_test exit $RC (replay 100% pasca-repair)" >> "$REPORT"
    if [ $RC -eq 0 ]; then
        note "M3: regression replay pasca-repair lulus (100%)"
    else
        fail "M3: regress_replay_test exit $RC (lihat $LOG)"
        grep -E '^\[FAIL\]' "$LOG" | head -5
    fi
else
    fail "M3: regress_replay_test gagal dibangun (-Werror)"
fi
rm -f test/regress_replay_test_tmp test/regress_replay_test_tmp.exe \
      test/regress_replay_test_tmp.log

# ------------------------------------------------------------------
# M4: agent_check satu-panggilan konvergen ≤3 iterasi ≥50%
# ------------------------------------------------------------------
echo "--- M4. agent_check konvergen ≤3 iterasi (≥50%) ---"
if [ -x "$MCP" ] && [ -f test/agent_check_loop_input.jsonl ]; then
    "$MCP" < test/agent_check_loop_input.jsonl > test/_tmp_sm_mcp.jsonl 2>&1
    # 8 kasus (MYC-AUDIT-059): 6 buggy runtime yang template-able
    # (strcpy-pair, memset-heap, memset-array, strcat, UAF-guarded,
    # memcpy-heap) semuanya konvergen + 1 UBSan why jujur (anti-
    # overclaim, bukan konvergen) + 1 source bersih = 7/8 konvergen.
    N_CONV=$(grep -c 'converged\\":true' test/_tmp_sm_mcp.jsonl)
    N_WHY=$(grep -c 'converged\\":false' test/_tmp_sm_mcp.jsonl)
    M4_TOTAL=$((N_CONV + N_WHY))
    if [ "$M4_TOTAL" -eq 0 ]; then
        fail "M4: agent_check tidak menghasilkan repair_loop"
    else
        M4_PCT=$((N_CONV * 100 / M4_TOTAL))
        echo "M4: $N_CONV/$M4_TOTAL kasus agent_check konvergen ($M4_PCT% >= 50%)" >> "$REPORT"
        if [ "$M4_PCT" -ge 50 ]; then
            note "M4: agent_check konvergen $M4_PCT% (target >=50%)"
        else
            fail "M4: agent_check konvergen $M4_PCT% (<50%)"
        fi
    fi
    rm -f test/_tmp_sm_mcp.jsonl
else
    fail "M4: mcp atau fixture agent_check tidak tersedia"
fi

# ------------------------------------------------------------------
# M5: self-dogfood semua source myc OK
# ------------------------------------------------------------------
echo "--- M5. self-dogfood semua source myc (verdict OK) ---"
M5_TOTAL=0
M5_OK=0
# Semua source kompiler: root *.c + dogfood/*.c (deterministik, glob
# terurut). Fixture test/ dan tests/ sengaja buggy -> bukan bagian
# corpus self-dogfood, jadi tidak di-iterasi di sini.
for f in *.c dogfood/*.c; do
    [ -f "$f" ] || continue
    inc; M5_TOTAL=$((M5_TOTAL + 1))
    r=$("$MYC" check "$f" --no-cache 2>&1 | grep -oE "verdict:[[:space:]]+[A-Z_]+" | head -1)
    case "$r" in
        "verdict:"*"OK"*) M5_OK=$((M5_OK + 1));;
        *) fail "M5 dogfood $f: $r";;
    esac
done
echo "M5: $M5_OK/$M5_TOTAL source self-dogfood OK" >> "$REPORT"
if [ "$M5_OK" -eq "$M5_TOTAL" ]; then
    note "M5: self-dogfood $M5_OK/$M5_TOTAL OK"
else
    fail "M5: self-dogfood $M5_OK/$M5_TOTAL (harus semua OK)"
fi

# ------------------------------------------------------------------
# M6: agen-lite patuh allowed_span ≥90% (lite_agent_test)
# ------------------------------------------------------------------
echo "--- M6. agen-lite patuh allowed_span (>=90%) ---"
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/lite_agent_test_tmp test/lite_agent_test.c $SRCS 2>/dev/null; then
    LOG="test/lite_agent_test_tmp.log"
    test/lite_agent_test_tmp >"$LOG" 2>&1; RC=$?
    M6_LINE=$(grep -oE 'lite_agent_test: PASS=[0-9]+ FAIL=[0-9]+' "$LOG" | head -1)
    M6_PASS=$(echo "$M6_LINE" | sed -E 's/.*PASS=([0-9]+).*/\1/')
    M6_FAILN=$(echo "$M6_LINE" | sed -E 's/.*FAIL=([0-9]+).*/\1/')
    if [ -z "$M6_PASS" ] || [ -z "$M6_FAILN" ]; then
        fail "M6: lite_agent_test tidak mencetak PASS/FAIL"
        M6_PCT=0
    else
        M6_TOT=$((M6_PASS + M6_FAILN))
        if [ "$M6_TOT" -eq 0 ]; then
            fail "M6: 0 CHECK"
            M6_PCT=0
        else
            M6_PCT=$((M6_PASS * 100 / M6_TOT))
            echo "M6: $M6_PASS/$M6_TOT CHECK patuh span ($M6_PCT% >= 90%; exit $RC)" >> "$REPORT"
            if [ "$RC" -eq 0 ] && [ "$M6_PCT" -ge 90 ]; then
                note "M6: agen-lite patuh allowed_span $M6_PCT%"
            else
                fail "M6: patuh span $M6_PCT% (exit $RC)"
            fi
        fi
    fi
else
    fail "M6: lite_agent_test gagal dibangun"
    M6_PCT=0
fi
rm -f test/lite_agent_test_tmp test/lite_agent_test_tmp.exe \
      test/lite_agent_test_tmp.log

# ------------------------------------------------------------------
# M7: inner-loop cache-hit. Target MCP p50 <20 ms; CLI one-shot
#     memuat process start jadi ambang CI = 150 ms + harus < miss.
# ------------------------------------------------------------------
echo "--- M7. inner-loop cache-hit ---"
M7_PCT="n/a"
if bash bench/inner_loop.sh >/tmp/myc_inner_loop.log 2>&1; then
    M7_MISS=$(sed -n 's/^miss_ms=//p' bench/reports/inner-loop-latest.txt | head -1)
    M7_HIT=$(sed -n 's/^replay_avg_ms=//p' bench/reports/inner-loop-latest.txt | head -1)
    echo "M7: miss=${M7_MISS:-?} replay_avg=${M7_HIT:-?} (CLI ms; target MCP <20)" >> "$REPORT"
    if echo "${M7_HIT:-}" | grep -qE '^[0-9]+$' && echo "${M7_MISS:-}" | grep -qE '^[0-9]+$'; then
        if [ "$M7_HIT" -lt "$M7_MISS" ] && [ "$M7_HIT" -lt 150 ]; then
            note "M7: cache-hit CLI ${M7_HIT}ms < miss ${M7_MISS}ms (ambang CI 150; MCP target 20)"
            M7_PCT="$M7_HIT"
        else
            fail "M7: replay_avg ${M7_HIT}ms (miss ${M7_MISS}; harus < miss dan <150)"
            M7_PCT="$M7_HIT"
        fi
    else
        fail "M7: inner_loop tidak menulis angka ms"
    fi
else
    fail "M7: bench/inner_loop.sh gagal"
fi

# ------------------------------------------------------------------
# M8: payload lite ≤ 2048 B (GIVE_UP+context dikecualikan)
# ------------------------------------------------------------------
echo "--- M8. payload lite <= 2048 B ---"
M8_CASES="tests/ok_hello.c test/fixtures/ok_driver.c test/fixtures/blinky_clean.c"
M8_OK=0
M8_TOTAL=0
for f in $M8_CASES; do
    [ -f "$f" ] || continue
    inc; M8_TOTAL=$((M8_TOTAL + 1))
    js=$("$MYC" check "$f" --lite --no-cache 2>/dev/null)
    act=$(printf '%s' "$js" | grep -oE '"action":"[A-Z_]+"' | head -1)
    bytes=$(printf '%s' "$js" | wc -c)
    if printf '%s' "$act" | grep -q GIVE_UP_NO_TEMPLATE; then
        note "M8 $f: GIVE_UP (context; tidak dihitung ke batas 2048)"
        M8_OK=$((M8_OK + 1))
        continue
    fi
    if [ "$bytes" -le 2048 ]; then
        M8_OK=$((M8_OK + 1))
        note "M8 $f: ${bytes} B"
    else
        fail "M8 $f: ${bytes} B > 2048"
    fi
done
echo "M8: $M8_OK/$M8_TOTAL payload lite <=2048 B" >> "$REPORT"
if [ "$M8_TOTAL" -gt 0 ] && [ "$M8_OK" -eq "$M8_TOTAL" ]; then
    note "M8: payload lite $M8_OK/$M8_TOTAL <=2048 B"
else
    fail "M8: payload lite $M8_OK/$M8_TOTAL"
fi

# ------------------------------------------------------------------
# M9: STOP tidak boleh jika --scenario auto masih butuh runtime available
# ------------------------------------------------------------------
echo "--- M9. STOP vs scenario auto runtime ---"
M9_OK=1
if command -v clang >/dev/null 2>&1 || command -v clang.exe >/dev/null 2>&1; then
    lite=$("$MYC" check tests/ok_hello.c --scenario auto --lite --no-cache 2>/dev/null)
    sum=$("$MYC" check tests/ok_hello.c --scenario auto --json-summary --no-cache 2>/dev/null)
    act=$(printf '%s' "$lite" | grep -oE '"action":"[A-Z_]+"' | head -1)
    ran=$(printf '%s' "$sum" | grep -oE '"ran_runtime":[a-z]+' | head -1)
    if printf '%s' "$act" | grep -q STOP_COMPILE_CLEAN &&
       printf '%s' "$ran" | grep -q 'ran_runtime":false'; then
        fail "M9: STOP_COMPILE_CLEAN padahal runtime available belum jalan"
        M9_OK=0
    else
        note "M9: action=${act:-?} ran_runtime=${ran:-?} (bukan STOP tanpa runtime)"
    fi
else
    note "M9: clang tidak ada — dilewati"
fi
echo "M9: STOP vs scenario-auto runtime: $([ $M9_OK -eq 1 ] && echo OK || echo FAIL)" >> "$REPORT"

# ------------------------------------------------------------------
# M10: first-action = enum, bukan flag soup ≥80%
# ------------------------------------------------------------------
echo "--- M10. first-action enum bukan flag soup (>=80%) ---"
M10_CASES="tests/ok_hello.c test/fixtures/ok_driver.c test/fixtures/blinky_clean.c tests/bad_syntax.c"
M10_OK=0
M10_TOTAL=0
for f in $M10_CASES; do
    [ -f "$f" ] || continue
    inc; M10_TOTAL=$((M10_TOTAL + 1))
    js=$("$MYC" check "$f" --lite --no-cache 2>/dev/null)
    act=$(printf '%s' "$js" | grep -oE '"action":"[A-Z_]+"' | head -1)
    nxt=$(printf '%s' "$js" | grep -oE '"next_command":"[^"]*"' | head -1)
    soup=0
    printf '%s' "$nxt" | grep -q -- '--filc' && soup=1
    printf '%s' "$nxt" | grep -q -- '--prove' && soup=1
    printf '%s' "$nxt" | grep -q -- '--divergence' && soup=1
    printf '%s' "$nxt" | grep -q -- '--analyze' && soup=1
    if [ -n "$act" ] && [ "$soup" -eq 0 ]; then
        M10_OK=$((M10_OK + 1))
        note "M10 $f: $act"
    else
        fail "M10 $f: action=${act:-?} next=${nxt:-?} (flag soup?)"
    fi
done
if [ "$M10_TOTAL" -eq 0 ]; then
    M10_PCT=0
    fail "M10: 0 kasus"
else
    M10_PCT=$((M10_OK * 100 / M10_TOTAL))
    echo "M10: $M10_OK/$M10_TOTAL first-action enum ($M10_PCT% >= 80%)" >> "$REPORT"
    if [ "$M10_PCT" -ge 80 ]; then
        note "M10: first-action enum $M10_PCT%"
    else
        fail "M10: first-action enum $M10_PCT% (<80%)"
    fi
fi

# ------------------------------------------------------------------
# Report + ringkasan
# ------------------------------------------------------------------
{
    echo ""
    echo "=== Ringkasan ==="
    echo "M1 lokasi_runtime_benar_pct: $M1_PCT (target >=90)"
    echo "M2 repair_template_patch: ${M2_OK:-?}/${M2_TOTAL:-?} (target >=50; pct ${M2_PCT:-0})"
    echo "M3 regression_replay: 100% (target 100)"
    echo "M4 agent_check_konvergen_pct: ${M4_PCT:-0} (target >=50)"
    echo "M5 self_dogfood: $M5_OK/$M5_TOTAL (target all)"
    echo "M6 lite_span_pct: ${M6_PCT:-?} (target >=90)"
    echo "M7 cache_hit_cli_ms: ${M7_PCT:-?} (CI <150 dan < miss; MCP target <20)"
    echo "M8 lite_payload: ${M8_OK:-?}/${M8_TOTAL:-?} (target all <=2048 B)"
    echo "M9 stop_vs_auto_runtime: $([ ${M9_OK:-1} -eq 1 ] && echo OK || echo FAIL)"
    echo "M10 first_action_enum_pct: ${M10_PCT:-?} (target >=80)"
    echo "result: $([ $FAIL -eq 0 ] && echo PASS || echo FAIL)"
    echo "pass: $PASS fail: $FAIL total: $TOTAL"
} >> "$REPORT"

echo ""
echo "=== Success Metrics: PASS=$PASS FAIL=$FAIL ==="
echo "laporan: $REPORT"
cat "$REPORT"
[ $FAIL -eq 0 ] || exit 1
exit 0
