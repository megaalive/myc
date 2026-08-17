#!/usr/bin/env bash
# bench/inner_loop.sh — G2: 1 miss + 9 comment-edits vs 9 identical replay.
# Tulis angka ke bench/reports/inner-loop-latest.txt
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p bench/reports test/_inner_loop
SRC=test/_inner_loop/loop.c
OUT=bench/reports/inner-loop-latest.txt
MYC=./myc
[ -x myc.exe ] && MYC=./myc.exe

cat > "$SRC" <<'EOF'
int add(int a, int b) { return a + b; }
EOF

rm -rf .myc/evidence_cache.json .myc/evidence_cache.sha256 2>/dev/null

miss_ms=$($MYC check "$SRC" --json-summary --no-assumptions 2>/dev/null \
  | sed -n 's/.*"duration_ms":\([0-9]*\).*/\1/p' | head -1)
echo "miss_ms=${miss_ms:-?}" > "$OUT"

# 9 replay identik
i=0
sum=0
n=0
while [ $i -lt 9 ]; do
  ms=$($MYC check "$SRC" --json-summary --no-assumptions 2>/dev/null \
    | sed -n 's/.*"duration_ms":\([0-9]*\).*/\1/p' | head -1)
  if [ -n "$ms" ]; then
    sum=$((sum + ms))
    n=$((n + 1))
  fi
  i=$((i + 1))
done
if [ "$n" -gt 0 ]; then
  echo "replay_avg_ms=$((sum / n))" >> "$OUT"
else
  echo "replay_avg_ms=?" >> "$OUT"
fi

# 9 edit komentar (source_sha berubah, cache miss atau delta)
i=0
sum=0
n=0
while [ $i -lt 9 ]; do
  printf 'int add(int a, int b) { return a + b; } /* %d */\n' "$i" > "$SRC"
  ms=$($MYC check "$SRC" --json-summary --no-assumptions 2>/dev/null \
    | sed -n 's/.*"duration_ms":\([0-9]*\).*/\1/p' | head -1)
  if [ -n "$ms" ]; then
    sum=$((sum + ms))
    n=$((n + 1))
  fi
  i=$((i + 1))
done
if [ "$n" -gt 0 ]; then
  echo "comment_edit_avg_ms=$((sum / n))" >> "$OUT"
else
  echo "comment_edit_avg_ms=?" >> "$OUT"
fi

echo "wrote $OUT"
cat "$OUT"
