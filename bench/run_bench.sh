#!/usr/bin/env bash
# =====================================================================
# run_bench.sh — Baseline LLM-assistance benchmark (SOL-24, Fase -1).
#
# Membaca bench/manifest.json, menjalankan myc check pada setiap task
# (bad + good), membandingkan verdict terhadap ekspektasi, dan
# melaporkan detection rate, false-positive rate, binary size,
# default latency, full-suite latency, dan agent payload size.
#
# - Verdict hard gate (COMPILE_ERROR/RUNTIME_VIOLATION/DRIVER_VIOLATION)
#   harus PERSIS sama dengan ekspektasi.
# - Task observasi NON-blocking (lint/negative/stack/perturb/thread-probe)
#   memakai "obs_pattern" (regex) yang harus muncul di output bad file;
#   tanpa obs_pattern, fallback ke 'lint:|[Oo]bserv'.
# - Report deterministik ditulis ke bench/reports/baseline-*.txt
#   (bash murni + python3; python3 opsional untuk parse manifest).
#
# Bebas dependensi eksternal (murni bash).
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

MYC="./myc"
[ -x "$MYC" ] || MYC="./myc.exe"
[ -x "$MYC" ] || { echo "[FAIL] myc tidak ditemukan (cari ./myc atau ./myc.exe)"; exit 1; }

MANIFEST="bench/manifest.json"
[ -f "$MANIFEST" ] || { echo "[FAIL] $MANIFEST tidak ada"; exit 1; }

REPORT_DIR="bench/reports"
mkdir -p "$REPORT_DIR"

PASS=0
FAIL=0
TOTAL=0

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

# now_ms → epoch ms (date +%s%N tidak didukung semua shell → fallback %s)
now_ms() {
    if command -v date >/dev/null 2>&1 && date +%s%N 2>/dev/null | grep -qE '^[0-9]{13,}$'; then
        echo $(( $(date +%s%N) / 1000000 ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

# run_check <file> <flags...> → verdict keyword (dan simpan ms via file temp,
# karena command-substitution berjalan di subshell)
# Selalu --no-cache: cache replay memotong detail observasi (benchmark harus
# deterministik + observasi lengkap).
LAST_MS_FILE="/tmp/bench_last_ms.$$"
run_check() {
    local file="$1"
    shift
    local t0 t1 out
    t0=$(now_ms)
    out=$("$MYC" check "$file" "$@" --no-cache 2>&1)
    t1=$(now_ms)
    echo $((t1 - t0)) > "$LAST_MS_FILE"
    printf '%s\n' "$out" | grep -oE 'verdict:[[:space:]]+[A-Z_]+' | head -1 | sed 's/verdict:[[:space:]]*//'
}

# run_obs <pattern> <file> <flags...> → 1 jika output mengandung pattern
run_obs() {
    local pattern="$1"
    local file="$2"
    shift 2
    "$MYC" check "$file" "$@" --no-cache 2>&1 | grep -qE "$pattern"
}

# agent payload size (bytes) untuk file referensi
PAYLOAD_REF="tests/ok_hello.c"
PAYLOAD_BYTES=$("$MYC" check "$PAYLOAD_REF" --agent 2>/dev/null | wc -c)
[ -z "$PAYLOAD_BYTES" ] || [ "$PAYLOAD_BYTES" = "0" ] && PAYLOAD_BYTES=$(wc -c < /dev/null)

# Binary size
BIN_SIZE=$(wc -c < "$MYC" 2>/dev/null || echo 0)

# Default latency = satu check dasar tanpa gate (ok_hello)
t0=$(now_ms)
"$MYC" check tests/ok_hello.c >/dev/null 2>&1
t1=$(now_ms)
DEFAULT_LATENCY_MS=$((t1 - t0))

echo "=== Baseline Benchmark ==="
echo "binary: $MYC ($BIN_SIZE bytes) | default check: ${DEFAULT_LATENCY_MS}ms | agent payload (ok_hello): ${PAYLOAD_BYTES}B"
echo ""

# Parsing manifest: ekstrak setiap task sebagai baris pipe-delimited
# Format: id|bad|good|flags|expect_bad|expect_good|has_obs|obs_pattern
TASK_LINES=()
while IFS= read -r line; do
    TASK_LINES+=("$line")
done < <(python3 -c "
import json, sys
with open('$MANIFEST') as f:
    data = json.load(f)
for t in data['tasks']:
    flags = ','.join(t.get('flags', []))
    has_obs = 'true' if t.get('expect_bad_has_observations') else 'false'
    pat = t.get('obs_pattern', '')
    print(f\"{t['id']}|{t['bad']}|{t['good']}|{flags}|{t['expect_bad']}|{t['expect_good']}|{has_obs}|{pat}\")
" 2>/dev/null)

# Fallback: jika python3 tidak tersedia, gunakan hardcoded task list
if [ ${#TASK_LINES[@]} -eq 0 ]; then
    TASK_LINES=(
      "t01-stack-oob|tests/bad_run_oob.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|false|"
      "t02-use-after-free|tests/bad_run_uaf.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|false|"
      "t03-int-overflow|tests/bad_run_intovf.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|false|"
      "t04-checked-direct|tests/bad_checked.c|tests/ok_checked.c|--checked|COMPILE_ERROR|OK|false|"
      "t05-checked-oob|tests/bad_checked_oob.c|tests/ok_checked.c|--run,--checked|RUNTIME_VIOLATION|OK|false|"
      "t06-malloc-return|tests/bad_realloc.c|tests/ok_hello.c||COMPILE_ERROR|OK|false|"
      "t07-driver-oob|test/fixtures/bad_driver_oob.c|test/fixtures/ok_driver.c|--driver|DRIVER_VIOLATION|OK|false|"
      "t08-contract-clauses|test/fixtures/contract_clauses.c|test/fixtures/ok_contract.c|--run|OK|OK|false|contract clauses"
      "t09-intptr-cast|tests/bad_intptr.c|tests/ok_hello.c||OK|OK|true|"
      "t10-negative-gap|tests/negative_dev.c|tests/negative_ok.c|--negative|OK|OK|true|"
      "t11-fuzz-lite|test/fixtures/bad_fuzz.c|test/fixtures/ok_fuzz.c|--fuzz,--fuzz-iters,300|DRIVER_VIOLATION|OK|false|"
      "t12-exhaustive|test/fixtures/bad_exhaustive.c|test/fixtures/ok_exhaustive.c|--exhaustive|DRIVER_VIOLATION|OK|false|"
      "t13-witness-oob|test/fixtures/witness_oob.c|test/fixtures/witness_clean.c|--run|RUNTIME_VIOLATION|OK|false|"
      "t14-freestanding|test/fixtures/blinky_bad.c|test/fixtures/blinky_clean.c|--freestanding|OK|OK|false|freestanding"
      "t15-checked-type|tests/bad_checked_type.c|tests/ok_checked.c|--checked|COMPILE_ERROR|OK|false|"
      "t16-syntax|tests/bad_syntax.c|tests/ok_hello.c||COMPILE_ERROR|OK|false|"
      "t17-oob-static|tests/bad_oob.c|tests/ok_bounds.c||COMPILE_ERROR|OK|false|"
      "t18-stack-recursion|test/fixtures/stack_recursive.c|tests/ok_hello.c|--stack|OK|OK|false|recursion"
      "t19-perturb-env|test/fixtures/pert_tz.c|tests/ok_hello.c|--run,--perturb|OK|OK|false|ENV-SENSITIVE"
      "t20-thread-probe|test/fixtures/con_inv.c|tests/ok_hello.c|--thread-probe|OK|OK|false|LOCK-ORDER INVERSION"
    )
fi

# Strip CRLF (file .sh disimpan CRLF di Windows; bash mempertahankan \r)
for i in "${!TASK_LINES[@]}"; do
    TASK_LINES[$i]=${TASK_LINES[$i]//$'\r'/}
done

echo "--- Detection (bad files) ---"
BAD_TOTAL=0
BAD_OK=0
SUITE_MS=0
for task in "${TASK_LINES[@]}"; do
    IFS='|' read -r id bad good flags expect_bad expect_good has_obs obs_pattern <<< "$task"
    BAD_TOTAL=$((BAD_TOTAL + 1))
    TOTAL=$((TOTAL + 1))

    IFS=',' read -ra flag_arr <<< "$flags"

    LAST_MS=0
    verdict=$(run_check "$bad" "${flag_arr[@]}")
    LAST_MS=$(cat "$LAST_MS_FILE" 2>/dev/null || echo 0)
    SUITE_MS=$((SUITE_MS + LAST_MS))

    if [ "$has_obs" = "true" ] || [ -n "${obs_pattern:-}" ]; then
        if [ -n "${obs_pattern:-}" ]; then
            if run_obs "$obs_pattern" "$bad" "${flag_arr[@]}"; then
                note "$id bad → observasi '$obs_pattern' ditemukan"
                BAD_OK=$((BAD_OK + 1))
            else
                fail "$id bad → observasi '$obs_pattern' TIDAK ditemukan"
            fi
        elif run_obs 'lint:|[Oo]bserv' "$bad" "${flag_arr[@]}"; then
            note "$id bad → observasi ditemukan (lint/negative non-blocking)"
            BAD_OK=$((BAD_OK + 1))
        else
            fail "$id bad → tidak ada observasi (expected lint/negative observations)"
        fi
        continue
    fi

    if [ "$verdict" = "$expect_bad" ]; then
        note "$id bad → $verdict (expected $expect_bad) [${LAST_MS}ms]"
        BAD_OK=$((BAD_OK + 1))
    else
        fail "$id bad → got '$verdict' (expected $expect_bad)"
    fi
done
echo ""

echo "--- False-positive check (good files) ---"
GOOD_TOTAL=0
GOOD_OK=0
for task in "${TASK_LINES[@]}"; do
    IFS='|' read -r id bad good flags expect_bad expect_good has_obs obs_pattern <<< "$task"
    GOOD_TOTAL=$((GOOD_TOTAL + 1))
    TOTAL=$((TOTAL + 1))

    IFS=',' read -ra flag_arr <<< "$flags"

    LAST_MS=0
    verdict=$(run_check "$good" "${flag_arr[@]}")
    LAST_MS=$(cat "$LAST_MS_FILE" 2>/dev/null || echo 0)
    SUITE_MS=$((SUITE_MS + LAST_MS))

    if [ "$verdict" = "$expect_good" ]; then
        note "$id good → $verdict (expected $expect_good) [${LAST_MS}ms]"
        GOOD_OK=$((GOOD_OK + 1))
    else
        fail "$id good → got '$verdict' (expected $expect_good)"
    fi
done
echo ""

echo "=== Summary ==="
echo "Tasks:              ${#TASK_LINES[@]}"
echo "Bad detected:       $BAD_OK / $BAD_TOTAL"
echo "Good clean:         $GOOD_OK / $GOOD_TOTAL"
echo "Binary size:        $BIN_SIZE bytes"
echo "Default latency:    ${DEFAULT_LATENCY_MS}ms (check ok_hello, tanpa gate)"
echo "Full-suite latency: ${SUITE_MS}ms (semua bad+good)"
echo "Agent payload:      ${PAYLOAD_BYTES}B (ok_hello --agent)"
if [ "$BAD_TOTAL" -gt 0 ]; then
    echo "Detection rate:     $(( BAD_OK * 100 / BAD_TOTAL ))%"
fi
if [ "$GOOD_TOTAL" -gt 0 ]; then
    echo "Good-pass rate:     $(( GOOD_OK * 100 / GOOD_TOTAL ))%"
fi
echo ""

# Tulis report deterministik (baseline-latest.txt + timestamped)
REPORT_STAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/baseline-$REPORT_STAMP.txt"
{
    echo "myc-assistance-baseline v1"
    echo "date: $REPORT_STAMP"
    echo "tasks: ${#TASK_LINES[@]}"
    echo "bad_detected: $BAD_OK / $BAD_TOTAL"
    echo "good_clean: $GOOD_OK / $GOOD_TOTAL"
    echo "binary_size: $BIN_SIZE"
    echo "default_latency_ms: $DEFAULT_LATENCY_MS"
    echo "suite_latency_ms: $SUITE_MS"
    echo "agent_payload_bytes: $PAYLOAD_BYTES"
    echo "detection_rate_pct: $(( BAD_TOTAL ? BAD_OK * 100 / BAD_TOTAL : 0 ))"
    echo "good_pass_rate_pct: $(( GOOD_TOTAL ? GOOD_OK * 100 / GOOD_TOTAL : 0 ))"
    echo "result: $([ "$FAIL" -gt 0 ] && echo FAIL || echo PASS)"
} > "$REPORT_FILE"
cp "$REPORT_FILE" "$REPORT_DIR/baseline-latest.txt"
echo "report: $REPORT_FILE"

if [ "$FAIL" -gt 0 ]; then
    echo "BENCHMARK: FAIL ($FAIL)"
    exit 1
else
    echo "BENCHMARK: PASS"
    exit 0
fi
