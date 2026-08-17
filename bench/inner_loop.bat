@echo off
rem bench/inner_loop.bat — G2: 1 miss + 9 replay identik (Windows).
setlocal
cd /d "%~dp0.."
if not exist bench\reports mkdir bench\reports
if not exist test\_inner_loop mkdir test\_inner_loop
set SRC=test\_inner_loop\loop.c
set OUT=bench\reports\inner-loop-latest.txt
echo int add(int a, int b) { return a + b; } > %SRC%
if exist .myc\evidence_cache.json del /q .myc\evidence_cache.json
if exist .myc\evidence_cache.sha256 del /q .myc\evidence_cache.sha256
echo inner_loop.bat: jalankan myc check 1 miss + 9 replay > %OUT%
myc.exe check %SRC% --json-summary --no-assumptions >> %OUT% 2>&1
for /L %%i in (1,1,9) do myc.exe check %SRC% --json-summary --no-assumptions >nul 2>&1
echo done. lihat %OUT%
