@echo off
rem _corpus_abuse.bat -- P9 corpus abuse: myc harus tetap memberi verdict
rem (tidak crash/hang) pada input ganas di test\corpus\*.c.
setlocal
set OUT=test\_tmp_corpus_out.txt
set FAIL=0
echo --- corpus abuse: cek setiap file ganas dengan --analyze
for %%f in (test\corpus\*.c) do (
  echo === %%f
  myc.exe check "%%f" --analyze > %OUT% 2>&1
  if errorlevel 3 (
    echo [CRASH/HANG?] %%f exit=%errorlevel%
    set FAIL=1
  ) else (
    findstr /B /C:"verdict:" %OUT% >nul || (
      echo [TANPA VERDICT] %%f
      set FAIL=1
    )
  )
)
echo --- corpus abuse: --run (pastikan tidak hang; timeout terkontrol)
for %%f in (test\corpus\recursive.c test\corpus\huge_line.c) do (
  echo === %%f
  myc.exe check "%%f" --run > %OUT% 2>&1
  if errorlevel 3 (
    echo [CRASH/HANG?] %%f exit=%errorlevel%
    set FAIL=1
  ) else (
    findstr /B /C:"verdict:" %OUT% >nul || (
      echo [TANPA VERDICT] %%f
      set FAIL=1
    )
  )
)
del %OUT%
if "%FAIL%"=="1" (
  echo [GAGAL] corpus abuse
  exit /b 1
)
echo [OK] corpus abuse lulus
exit /b 0
