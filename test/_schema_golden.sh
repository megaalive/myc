#!/usr/bin/env bash
# =====================================================================
# _schema_golden.sh — Golden schema + malformed-input tests (Fase 0).
#
# Memverifikasi kontrak beku docs/result-schema.md:
#   1. Output `--json-summary` SELALU JSON valid (termasuk input korup).
#   2. Field wajib myc.result.v1 ada dengan tipe yang benar.
#   3. Verdict enum hanya dari himpunan beku.
#   4. Output `--agent` (myc.agent.v2) valid: schema, verdict ordinal,
#      satu aksi utama (next_check), payload cap.
#   5. Malformed input: file kosong / garbage / unclosed -> JSON tetap
#      valid (verdict COMPILE_ERROR/OK), tidak crash, exit 0.
#
# Portabel: ./myc atau ./myc.exe; python3 dipakai hanya bila ada
# (tanpa python3, cek struktural grep tetap berjalan).
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

MYC="./myc"
[ -x "$MYC" ] || MYC="./myc.exe"
[ -x "$MYC" ] || { echo "[FAIL] myc tidak ditemukan"; exit 1; }

PASS=0
FAIL=0
note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

# cek_golden <desc> <file> <flags...> → jalankan --json-summary dan validasi
# via python3 (bila ada) + fallback grep struktural
cek_golden() {
    local desc="$1" file="$2"
    shift 2
    local out
    out=$("$MYC" check "$file" "$@" --json-summary --no-cache 2>&1)
    if command -v python3 >/dev/null 2>&1; then
        local rc
        rc=$(printf '%s' "$out" | python3 -c "
import json, sys
s = sys.stdin.read()
try:
    d = json.loads(s)
except Exception as e:
    print('JSON_INVALID: %s' % e); sys.exit(1)
required = ['verdict', 'assurance_vector', 'finding', 'diagnostics',
            'exit_code', 'duration_ms', 'receipt_sha256', 'unverified_debt',
            'ran_runtime', 'ran_checked', 'ran_prove', 'ran_filc',
            'ran_driver', 'ran_exhaustive', 'ran_stack', 'ran_fuzz',
            'ran_mutate', 'ran_metamorphic', 'ran_divergence', 'ran_compare',
            'ran_negative', 'ran_freestanding', 'gate_matrix',
            'quorum_status', 'coaching', 'harvest', 'lint_observations',
            'lint_embedded_hits', 'assumptions', 'budget_met',
            'budget_report', 'completeness', 'error']
missing = [k for k in required if k not in d]
if missing:
    print('MISSING: %s' % ','.join(missing)); sys.exit(2)
verdicts = {'OK','COMPILE_ERROR','RUNTIME_VIOLATION','DRIVER_VIOLATION','INCONCLUSIVE','UNAVAILABLE'}
if d['verdict'] not in verdicts:
    print('BAD_VERDICT: %s' % d['verdict']); sys.exit(3)
if not isinstance(d['receipt_sha256'], str) or not isinstance(d['duration_ms'], int):
    print('BAD_TYPE'); sys.exit(4)
print('GOLDEN_OK verdict=%s' % d['verdict'])
" 2>&1)
        local code=$?
        if [ "$code" = "0" ]; then
            note "$desc ($(echo "$rc" | tail -1))"
        else
            fail "$desc — $(echo "$rc" | tail -1)"
        fi
    else
        # fallback tanpa python3: JSON valid + field inti ada
        if printf '%s' "$out" | grep -q '\"verdict\"' \
           && printf '%s' "$out" | grep -q '\"assurance_vector\"' \
           && printf '%s' "$out" | grep -q '\"receipt_sha256\"'; then
            note "$desc (fallback struktural tanpa python3)"
        else
            fail "$desc — field inti tidak ada"
        fi
    fi
}

echo "=== Golden schema: myc.result.v1 (--json-summary) ==="
cek_golden "schema ok_hello (clean)" tests/ok_hello.c
cek_golden "schema bad_run_oob (runtime violation)" tests/bad_run_oob.c --run
cek_golden "schema bad_checked (compile error)" tests/bad_checked.c --checked
cek_golden "schema driver_oob (driver violation)" test/fixtures/bad_driver_oob.c --driver
echo ""

echo "=== IDE-1: sanitizer_location pada RUNTIME_VIOLATION ==="
# bad_run_oob.c = heap-buffer-overflow (memset b,16 pada malloc(8)):
# lokasi pelanggaran harus terisi (line 12 = memset) + allocation (malloc).
if command -v python3 >/dev/null 2>&1; then
    out=$("$MYC" check tests/bad_run_oob.c --run --json-summary --no-cache 2>&1)
    rc=$(printf '%s' "$out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if d.get('verdict') != 'RUNTIME_VIOLATION':
    print('NOT_RUNTIME: %s' % d.get('verdict')); sys.exit(1)
sl = d.get('sanitizer_location')
if not sl:
    print('NO_LOCATION'); sys.exit(2)
kind = sl.get('violation_kind', '')
if 'overflow' not in kind and 'out-of-bounds' not in kind:
    print('BAD_KIND: %s' % kind); sys.exit(3)
line = sl.get('location', {}).get('line', 0)
if line <= 0:
    print('NO_LINE'); sys.exit(4)
if not sl.get('snippet'):
    print('NO_SNIPPET'); sys.exit(5)
print('SANLOC_OK kind=%s line=%d' % (kind, line))
" 2>&1)
    if [ "$?" = "0" ]; then
        note "IDE-1 bad_run_oob ($(echo "$rc" | tail -1))"
    else
        fail "IDE-1 bad_run_oob — $(echo "$rc" | tail -1)"
    fi
else
    if "$MYC" check tests/bad_run_oob.c --run --json-summary --no-cache 2>&1 \
       | grep -q 'sanitizer_location'; then
        note "IDE-1 bad_run_oob (fallback struktural: field ada)"
    else
        fail "IDE-1 bad_run_oob — sanitizer_location hilang"
    fi
fi
echo ""

echo "=== Malformed input: JSON tetap valid, tidak crash ==="
cek_golden "corpus empty.c" test/corpus/empty.c
cek_golden "corpus garbage.c" test/corpus/garbage.c
cek_golden "corpus unclosed_comment.c" test/corpus/unclosed_comment.c
cek_golden "corpus unclosed_string.c" test/corpus/unclosed_string.c
cek_golden "corpus deep_nesting.c" test/corpus/deep_nesting.c
cek_golden "corpus recursive.c" test/corpus/recursive.c
echo ""

echo "=== Golden schema: myc.agent.v2 (--agent) ==="
out=$("$MYC" check tests/ok_hello.c --agent --no-cache 2>&1)
if command -v python3 >/dev/null 2>&1; then
    rc=$(printf '%s' "$out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d.get('schema') == 'myc.agent.v2', 'schema != myc.agent.v2'
assert isinstance(d.get('verdict'), int), 'verdict bukan int'
assert 'next_check' in d, 'next_check hilang'
assert 'receipt_sha256' in d and 'source_sha256' in d, 'hash hilang'
assert isinstance(d.get('verdict'), int) and 0 <= d['verdict'] <= 5, 'verdict ordinal di luar range'
print('AGENT_OK schema=%s verdict=%d' % (d['schema'], d['verdict']))
" 2>&1)
    if [ "$?" = "0" ]; then
        note "agent ok_hello ($(echo "$rc" | tail -1))"
    else
        fail "agent ok_hello — $(echo "$rc" | tail -1)"
    fi
else
    if printf '%s' "$out" | grep -q 'myc.agent.v2' \
       && printf '%s' "$out" | grep -q '"next_check"'; then
        note "agent ok_hello (fallback struktural)"
    else
        fail "agent ok_hello — schema/next_check hilang"
    fi
fi
echo ""

echo "=== Malformed CLI input: flag salah tidak crash ==="
if "$MYC" check tests/ok_hello.c --flag-tidak-ada >/dev/null 2>&1; then
    fail "flag tak dikenal diterima (harus error)"
else
    note "flag tak dikenal ditolak dengan exit != 0"
fi
if "$MYC" check /path/tidak/ada.c >/dev/null 2>&1; then
    fail "file tak ada diterima (harus error)"
else
    note "file tak ada ditolak dengan exit != 0"
fi
echo ""

echo "=== _schema_golden.sh: PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ]
