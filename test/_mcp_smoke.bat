@echo off
rem _mcp_smoke.bat -- smoke test mcp.exe (P9): pipa JSON-RPC dan cek respons.
setlocal
set OUT=test\_tmp_mcp_out.txt
echo --- mcp smoke: initialize/ping/tools-list/tools-call
mcp.exe < test\mcp_smoke_input.jsonl > %OUT% 2>nul
if errorlevel 1 (
  echo [FAIL] mcp.exe tidak berjalan
  exit /b 1
)
echo --- respons (%OUT%)
rem 15 pesan ber-id = 15 baris respons JSON (notification tidak dijawab;
rem MYC-AUDIT-016: jsonrpc != "2.0" = -32600; flag tak dikenal = -32602;
rem check = structuredContent + schema).
rem Catatan: pakai for /f (bukan find /c) karena PATH bisa menunjuk ke GNU
rem find dari Git Bash yang sintaksnya beda.
set N=0
for /f "usebackq delims=" %%L in ("%OUT%") do set /a N+=1
if not "%N%"=="15" ( echo [FAIL] jumlah respons ^(%N%^) & exit /b 1 )
findstr /C:"serverInfo" %OUT% >nul || ( echo [FAIL] initialize & exit /b 1 )
findstr /C:"verdict" %OUT% | findstr /C:"OK" >nul || ( echo [FAIL] check ok & exit /b 1 )
findstr /C:"RUNTIME_VIOLATION" %OUT% >nul || ( echo [FAIL] check run & exit /b 1 )
findstr /C:"myc 0.1.0" %OUT% >nul || ( echo [FAIL] version & exit /b 1 )
findstr /C:"Unknown tool" %OUT% >nul || ( echo [FAIL] tool tidak dikenal & exit /b 1 )
findstr /C:"-32602" %OUT% >nul || ( echo [FAIL] invalid params & exit /b 1 )
findstr /C:"-32600" %OUT% >nul || ( echo [FAIL] jsonrpc ketat & exit /b 1 )
findstr /C:"structuredContent" %OUT% >nul || ( echo [FAIL] structuredContent & exit /b 1 )
findstr /C:"myc.result.v1" %OUT% >nul || ( echo [FAIL] schema version & exit /b 1 )
findstr /C:"tools" %OUT% >nul || ( echo [FAIL] tools/list & exit /b 1 )
findstr /C:"contracts: requires=1 ensures=1" %OUT% >nul || ( echo [FAIL] tool contracts & exit /b 1 )
rem MYC-AUDIT-014: tool lint = observasi ber-confidence (non-blocking),
rem bukan verdict VIOLATION.
findstr /C:"observasi" %OUT% | findstr /C:"lint" >nul || ( echo [FAIL] tool lint & exit /b 1 )
rem MYC-AUDIT-039: agent_check + pack proyek (pack_dir) -> pack_present
findstr /C:"pack_present" %OUT% >nul || ( echo [FAIL] agent_check pack_present & exit /b 1 )
findstr /C:"prompt_present" %OUT% >nul || ( echo [FAIL] agent_check pack isi & exit /b 1 )
rem MYC-AUDIT-039: pack_bad (spec invalid) -> error -32602 (fail-fast)
findstr /C:"myc.spec.json invalid" %OUT% >nul || ( echo [FAIL] agent_check pack_bad & exit /b 1 )
echo [OK] mcp smoke lulus
del %OUT%
exit /b 0
