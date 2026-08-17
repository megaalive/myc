#!/usr/bin/env bash
# build.sh -- build myc tanpa dependensi eksternal (gcc), mirror POSIX dari
# build.bat. Menghasilkan `myc`, `mcp` (MCP server, P9), dan `argv_probe` di
# direktori ini. Dipakai CI Linux (MYC-AUDIT-023) dan pengembangan WSL.
set -eu
cd "$(dirname "$0")"

GCC="${GCC:-gcc}"
PIPELINE="myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c sanloc.c contract.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c prove.c filc.c driver.c exhaustive.c fuzz.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c persist.c limit.c alloc.c"
FLAGS="-O2 -std=c11 -Wall -Wextra -pthread"
# P11: rilis GitHub men-stempel SHA commit. SHA hex, aman sebagai token -D.
if [ -n "${MYC_GIT_SHA:-}" ]; then
    FLAGS="$FLAGS -DMYC_GIT_SHA=${MYC_GIT_SHA}"
fi

echo "[build] myc"
$GCC $FLAGS -o myc $PIPELINE

echo "[build] mcp"
$GCC $FLAGS -DMYC_NO_MAIN -o mcp mcp.c $PIPELINE

echo "[build] argv_probe"
$GCC $FLAGS -o argv_probe argv_probe.c

echo "[ok] myc, mcp, dan argv_probe selesai"
