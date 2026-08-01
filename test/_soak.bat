@echo off
rem _soak.bat -- P9 soak: jalankan pipeline berulang untuk stabilitas
rem (bukan correctness; cukup pastikan verdict konsisten, tanpa crash).
setlocal
set OUT=test\_tmp_soak_out.txt
echo --- soak: 20x myc check myc.c --analyze
for /L %%i in (1,1,20) do (
  myc.exe check myc.c --analyze > %OUT% 2>&1
  findstr /B /C:"verdict:" %OUT% | findstr /C:"OK" >nul || (
    echo [GAGAL] iterasi %%i
    del %OUT%
    exit /b 1
  )
)
echo --- soak: 10x myc check tests\ok_run.c --run
for /L %%i in (1,1,10) do (
  myc.exe check tests\ok_run.c --run > %OUT% 2>&1
  findstr /B /C:"verdict:" %OUT% >nul || (
    echo [GAGAL] iterasi %%i
    del %OUT%
    exit /b 1
  )
)
del %OUT%
echo [OK] soak lulus
exit /b 0
