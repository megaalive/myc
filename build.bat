@echo off
rem build.bat -- build myc tanpa dependensi eksternal (gcc + Makefile-style).
rem Menghasilkan myc.exe dan argv_probe.exe di folder ini.

setlocal
set GCC=gcc
set SRC=myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c
set FLAGS=-O2 -std=c11 -Wall -Wextra -o myc.exe

echo [build] myc.exe
%GCC% %FLAGS% %SRC%
if errorlevel 1 goto :err

echo [build] argv_probe.exe
%GCC% -O2 -std=c11 -Wall -Wextra -o argv_probe.exe argv_probe.c
if errorlevel 1 goto :err

echo [ok] myc.exe dan argv_probe.exe selesai
exit /b 0

:err
echo [gagal] build tidak selesai
exit /b 1
