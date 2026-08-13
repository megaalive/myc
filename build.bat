@echo off
rem build.bat -- build myc tanpa dependensi eksternal (gcc + Makefile-style).
rem Menghasilkan myc.exe, mcp.exe (MCP server, P9), dan argv_probe.exe.

setlocal
set GCC=gcc
set PIPELINE=myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c prove.c filc.c driver.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c persist.c limit.c alloc.c
set FLAGS=-O2 -std=c11 -Wall -Wextra

echo [build] myc.exe
%GCC% %FLAGS% -o myc.exe %PIPELINE%
if errorlevel 1 goto :err

echo [build] mcp.exe
%GCC% %FLAGS% -DMYC_NO_MAIN -o mcp.exe mcp.c %PIPELINE%
if errorlevel 1 goto :err

echo [build] argv_probe.exe
%GCC% %FLAGS% -o argv_probe.exe argv_probe.c
if errorlevel 1 goto :err

echo [ok] myc.exe, mcp.exe, dan argv_probe.exe selesai
exit /b 0

:err
echo [gagal] build tidak selesai
exit /b 1
