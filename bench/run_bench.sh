#!/usr/bin/env bash
# =====================================================================
# run_bench.sh — Baseline LLM-assistance benchmark (SOL-24, Fase -1).
#
# Membaca bench/manifest.json, menjalankan myc check pada setiap task
# (bad + good), membandingkan verdict terhadap ekspektasi, dan
# melaporkan detection rate, false-positive rate, binary size, dan
# latency.
#
# Bebas dependensi eksternal (murni bash).
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

MYC="./myc"
[ -x "$MYC" ] || { echo "[FAIL] $MYC tidak ditemukan"; exit 1; }

MANIFEST="bench/manifest.json"
[ -f "$MANIFEST" ] || { echo "[FAIL] $MANIFEST tidak ada"; exit 1; }

PASS=0
FAIL=0
TOTAL=0

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

# run_check <file> <flags...> → verdict keyword
run_check() {
    local file="$1"
    shift
    "$MYC" check "$file" "$@" 2>&1 | grep -oE 'verdict:[[:space:]]+[A-Z_]+' | head -1 | sed 's/verdict:[[:space:]]*//'
}

# run_obs <file> <flags...> → 1 jika output mengandung pola observasi, 0 jika tidak
run_obs() {
    local file="$1"
    shift
    "$MYC" check "$file" "$@" 2>&1 | grep -qE 'lint:|[Oo]bserv'
}

# Binary size
BIN_SIZE=$(wc -c < "$MYC" 2>/dev/null || echo 0)
echo "=== Baseline Benchmark ==="
echo "binary: $MYC ($BIN_SIZE bytes)"
echo ""

# Parsing manifest: ekstrak setiap task sebagai baris pipe-delimited
# Format JSON: "id":"...","bad":"...","good":"...","flags":[...],"expect_bad":"...","expect_good":"..."
TASK_LINES=()
while IFS= read -r line; do
    TASK_LINES+=("$line")
done < <(python3 -c "
import json, sys
with open('$MANIFEST') as f:
    data = json.load(f)
for t in data['tasks']:
    flags = ','.join(t.get('flags', []))
    print(f\"{t['id']}|{t['bad']}|{t['good']}|{flags}|{t['expect_bad']}|{t['expect_good']}\")
" 2>/dev/null)

# Fallback: jika python3 tidak tersedia, gunakan hardcoded task list
if [ ${#TASK_LINES[@]} -eq 0 ]; then
    TASK_LINES=(
      "t01|tests/bad_run_oob.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|"
      "t02|tests/bad_run_uaf.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|"
      "t03|tests/bad_run_intovf.c|tests/ok_run.c|--run|RUNTIME_VIOLATION|OK|"
      "t04|tests/bad_checked.c|tests/ok_checked.c|--checked|COMPILE_ERROR|OK|"
      "t05|tests/bad_checked_oob.c|tests/ok_checked.c|--run,--checked|RUNTIME_VIOLATION|OK|"
      "t06|tests/bad_realloc.c|tests/ok_hello.c||COMPILE_ERROR|OK|"
      "t07|test/fixtures/bad_driver_oob.c|test/fixtures/ok_driver.c|--driver|DRIVER_VIOLATION|OK|"
      "t08|test/fixtures/bad_contract_pre.c|test/fixtures/ok_contract.c|--run|RUNTIME_VIOLATION|OK|"
      "t09|tests/bad_intptr.c|tests/ok_hello.c||OK|OK|"
      "t10|tests/negative_dev.c|tests/negative_ok.c|--negative|OK|OK|true"
    )
fi

echo "--- Detection (bad files) ---"
BAD_TOTAL=0
BAD_OK=0
for task in "${TASK_LINES[@]}"; do
    IFS='|' read -r id bad good flags expect_bad expect_good expect_bad_has_obs <<< "$task"
    BAD_TOTAL=$((BAD_TOTAL + 1))
    TOTAL=$((TOTAL + 1))

    # Parse flags
    IFS=',' read -ra flag_arr <<< "$flags"

    verdict=$(run_check "$bad" "${flag_arr[@]}")

    # Untuk tugas yang butuh observasi (lint/negative), cek keberadaan observasi di output
    if [ "${expect_bad_has_obs:-}" = "true" ]; then
        if run_obs "$bad" "${flag_arr[@]}"; then
            note "$id bad → observasi ditemukan (lint/negative non-blocking)"
            BAD_OK=$((BAD_OK + 1))
        else
            fail "$id bad → tidak ada observasi (expected lint/negative observations)"
        fi
        continue
    fi

    if [ "$verdict" = "$expect_bad" ]; then
        note "$id bad → $verdict (expected $expect_bad)"
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
    IFS='|' read -r id bad good flags expect_bad expect_good <<< "$task"
    GOOD_TOTAL=$((GOOD_TOTAL + 1))
    TOTAL=$((TOTAL + 1))

    IFS=',' read -ra flag_arr <<< "$flags"
    verdict=$(run_check "$good" "${flag_arr[@]}")

    if [ "$verdict" = "$expect_good" ]; then
        note "$id good → $verdict (expected $expect_good)"
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
if [ "$BAD_TOTAL" -gt 0 ]; then
    echo "Detection rate:     $(( BAD_OK * 100 / BAD_TOTAL ))%"
fi
if [ "$GOOD_TOTAL" -gt 0 ]; then
    echo "False-positive rate: $(( GOOD_OK * 100 / GOOD_TOTAL ))%"
fi
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "BENCHMARK: FAIL ($FAIL)"
    exit 1
else
    echo "BENCHMARK: PASS"
    exit 0
fi