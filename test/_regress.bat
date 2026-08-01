@echo off
setlocal
for %%f in (tests\*.c test\fixtures\*.c) do (
  echo === %%f
  myc.exe check "%%f" > test\_tmp_out.txt
  findstr /B /C:"verdict:" /C:"assurance:" test\_tmp_out.txt
)
del test\_tmp_out.txt
exit /b 0
