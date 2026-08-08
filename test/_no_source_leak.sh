#!/usr/bin/env bash
# =====================================================================
# _no_source_leak.sh -- No-source-leak test (Fase 8, Definition of Done).
#
# Menegaskan bahwa output myc TIDAK membocorkan source user verbatim:
#   - --agent      : payload JSON hanya memuat hash source_sha256
#   - --json-summary : sama
#   - report teks  : tidak memuat baris source
#
# Fixture leak_probe.c memuat sentinel unik MYC_LEAK_SENTINEL_9137_...
# yang TIDAK boleh muncul di saluran mana pun. Bila sentinel muncul,
# terjadi leak -> FAIL (regresi kelas privacy tertangkap).
#
# Portabel: Windows (myc.exe) + POSIX (myc). CWD harus root repo.
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
SENTINEL="MYC_LEAK_SENTINEL_9137"
FIXTURE="test/fixtures/leak_probe.c"

note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=1; }

expect_no_leak() { # expect_no_leak <desc> <hash_field> <flags...>
    local desc="$1" hash_field="$2"
    shift 2
    local out
    out=$("$MYC" check "$FIXTURE" "$@" --no-cache 2>&1)
    if echo "$out" | grep -q "$SENTINEL"; then
        fail "$desc (sentinel BOCOR ke output!)"
    elif echo "$out" | grep -q "$hash_field"; then
        note "$desc (source hanya hash, tanpa konten)"
    else
        fail "$desc ($hash_field tidak ada)"
    fi
}

echo "=== No-source-leak test (Fase 8 DoD) ==="

expect_no_leak "agent payload tidak membocorkan source" source_sha256 --agent
expect_no_leak "json-summary tidak membocorkan source" receipt_sha256 --json-summary
expect_no_leak "report teks tidak membocorkan source" receipt_sha256

# Determinisme hash: source_sha256 harus sama lintas dua run (format compact)
H1=$("$MYC" check "$FIXTURE" --agent --no-cache 2>&1 | grep -o 'source_sha256":"[a-f0-9]*' | head -1)
H2=$("$MYC" check "$FIXTURE" --agent --no-cache 2>&1 | grep -o 'source_sha256":"[a-f0-9]*' | head -1)
if [ -n "$H1" ] && [ "$H1" = "$H2" ]; then
    note "source_sha256 deterministik lintas run"
else
    fail "source_sha256 tidak deterministik (hash berubah tiap run)"
fi

echo "=== _no_source_leak.sh: PASS=$PASS FAIL=$FAIL ==="
exit $FAIL
