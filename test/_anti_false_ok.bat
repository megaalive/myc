@echo off
rem _anti_false_ok.bat -- guard anti-false-OK (MYC-AUDIT-031).
rem
rem Pastikan myc BENAR-BENAR menjalankan gcc/sanitizer dan menolak input
rem rusak. Sejarah: bug STARTUPINFOEX membuat seluruh peluncuran gcc gagal
rem diam-diam di Windows, namun gerbang preprocess/compile/analyzer mengabaikan
rem nilai kembalian myc_proc_run sehingga program RUSAK dilaporkan "verdict: OK"
rem (false-OK). Guard ini gagal (exit /b 1) bila fixture negatif tidak lagi
rem menghasilkan verdict negatif -- sehingga regresi kelas false-OK tertangkap
rem di CI.
rem
rem Dijalankan dari direktori root repo (myc.exe & tests/ relatif).

setlocal
set "OUT=%TEMP%\myc_anti_false_ok.txt"
set "FAIL=0"

call :expect tests\bad_syntax.c  --no-lint COMPILE_ERROR     "basic syntax error"
call :expect tests\bad_oob.c      --no-lint COMPILE_ERROR     "basic OOB gcc memory tier"
call :expect tests\bad_realloc.c  --no-lint COMPILE_ERROR     "basic realloc UAF"
call :expect tests\bad_checked.c  --checked  COMPILE_ERROR     "checked direct b[i]"
call :expect tests\bad_run_oob.c  --run      RUNTIME_VIOLATION "run OOB via ASan"
call :expect tests\ok_run.c       --run      "verdict:   OK"   "run ok_run stays OK"

if "%FAIL%"=="0" (
  echo [OK] anti-false-OK guard lulus
  exit /b 0
)
echo [FATAL] anti-false-OK guard GAGAL
exit /b 1

:expect
set "F=%~1"
set "FLAGS=%~2"
set "WANT=%~3"
set "DESC=%~4"
myc.exe check "%F%" %FLAGS% > "%OUT%" 2>&1
findstr /C:"%WANT%" "%OUT%" >nul
if errorlevel 1 (
  echo [FAIL] %DESC% -- diharapkan mengandung "%WANT%"
  set "FAIL=1"
) else (
  echo [OK] %DESC%
)
goto :eof
