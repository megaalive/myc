#!/usr/bin/env bash
# =====================================================================
# _cap_sync.sh -- Kemampuan registry sync check (SOL-23).
#
# Verifikasi single source of truth `capabilities.json` tetap konsisten
# dengan:
#   1. implementasi: CLI flags di myc.c, MCP tools di mcp.c, schema di
#      mcp.c/report.c
#   2. dokumentasi: README.md, docs/capabilities.md, docs/mcp-tools.md
#
# Sumber kebenaran = capabilities.json. Edit di sana dulu; bila doc atau
# source tidak sinkron, check ini [FAIL]. Dijalankan dari _ci_linux.sh
# (POSIX) dan _regress_run.bat (Windows) via `where bash`.
#
# Bebas dependensi eksternal (murni bash + grep).
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

REG="capabilities.json"
[ -f "$REG" ] || { echo "[FAIL] $REG tidak ada"; exit 1; }

FAIL=0
PASS=0
note() { echo "[OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=1; }
# ada <desc> <pola> <file> -- pola literal (grep -F), 0 = ada
ada() {
    local desc="$1" pat="$2" file="$3"
    if grep -qF -- "$pat" "$file"; then
        note "$desc"
    else
        fail "$desc (tidak ada: $pat di $file)"
    fi
}

# --- 0. JSON punya bagian wajib ---
for key in schema_version gates cli_flags mcp_tools schemas dimensions; do
    grep -q "\"$key\"" "$REG" && note "capabilities.json punya $key" \
        || fail "capabilities.json kehilangan $key"
done

# --- 1. tiap gate di capabilities.json didokumentasikan di docs/capabilities.md ---
#     (pola dicocokkan dari kolom Gate, dibatasi sebelum karakter | )
while read -r gid; do
    [ -n "$gid" ] || continue
    if grep -qE "^\| $gid([[:space:]]|\|)" docs/capabilities.md; then
        note "gate $gid didokumentasikan di capabilities.md"
    else
        fail "gate $gid TIDAK ada sebagai baris tabel di capabilities.md"
    fi
done < <(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REG" | sort -u)

# --- 2. tiap CLI flag di capabilities.json terimplementasi di myc.c ---
while read -r fl; do
    [ -n "$fl" ] || continue
    ada "flag $fl terimplementasi di myc.c" "$fl" myc.c
done < <(sed -n '/"cli_flags"/,/]/p' "$REG" | grep -oE '"[-][a-zA-Z0-9-]+"' | tr -d '"' | sort -u)

# --- 3. tiap flag yang terdokumentasi di README (blok Usage) terdaftar di registry ---
while read -r fl; do
    [ -n "$fl" ] || continue
    grep -q "\"$fl\"" "$REG" && note "README flag $fl tercatat di capabilities.json" \
        || fail "README flag $fl TIDAK di capabilities.json (tambah/hapus dari registry)"
done < <(sed -n '/```/,/```/p' README.md | grep -oE '\-\-[a-zA-Z0-9-]+' | sort -u)

# --- 4. tiap MCP tool di registry ada di mcp.c dan docs/mcp-tools.md ---
while read -r t; do
    [ -n "$t" ] || continue
    ada "MCP tool $t di mcp.c" "\"$t\"" mcp.c
    if grep -qE "^### .*$t" docs/mcp-tools.md; then
        note "MCP tool $t didokumentasikan di mcp-tools.md"
    else
        fail "MCP tool $t TIDAK ada sebagai seksi di mcp-tools.md"
    fi
done < <(sed -n '/"mcp_tools"/,/]/p' "$REG" | grep -oE '"(check|repair|version|policy|contracts|lint)"' | tr -d '"' | sort -u)

# --- 5. tiap schema di registry terdeklarasi di mcp.c + didokumentasikan ---
while read -r s; do
    [ -n "$s" ] || continue
    ada "schema $s di mcp.c" "$s" mcp.c
    ada "schema $s didokumentasikan di mcp-tools.md" "$s" docs/mcp-tools.md
done < <(sed -n '/"schemas"/,/]/p' "$REG" | grep -oE '"myc\.[a-zA-Z.]+\.v1"' | tr -d '"' | sort -u)

# --- 6. tiap dimensi assurance C/S/R/B/P/D/F disebut di capabilities.md ---
for d in C S R B P D F; do
    grep -qF "$d" docs/capabilities.md && note "dimensi assurance $d di capabilities.md" \
        || fail "dimensi assurance $d TIDAK di capabilities.md"
done

echo "=== _cap_sync.sh: PASS=$PASS FAIL=$FAIL ==="
exit $FAIL