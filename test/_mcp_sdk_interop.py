#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_mcp_sdk_interop.py -- Uji interop mcp.exe dengan SDK MCP Python RESMI.

Berbeda dengan mcp_client.py (client stdio buatan sendiri), script ini
memakai paket resmi `mcp` (pip install mcp) -- stdio_client +
ClientSession -- sehingga membuktikan mcp.exe interoperable dengan harness
MCP standar (handshake, tools/list, tools/call).

Usage:
    python test/_mcp_sdk_interop.py [path_ke_mcp.exe]

Kode keluar 0 = semua cek lulus; 1 = ada kegagalan; 2 = SDK tidak terpasang.
"""

import asyncio
import os
import sys
import time

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("[SKIP] SDK MCP Python tidak terpasang (pip install mcp)")
    sys.exit(2)


def _exe_default():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mcp.exe")


def _read_source(subdir, name):
    """Baca isi file source di subdirektori relatif ke test/ (mis. "fixtures"
    atau "../tests") sebagai teks UTF-8. Membuka file dengan with-block."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        subdir, name)
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def _fixture_source(name):
    """Baca isi fixture di test/fixtures sebagai teks UTF-8."""
    return _read_source("fixtures", name)


def _tests_source(name):
    """Baca isi fixture di tests/ (mis. ok_checked.c) sebagai teks UTF-8."""
    return _read_source(os.path.join("..", "tests"), name)


SAFE_SRC = (
    "#include <stdlib.h>\n"
    "int main(void){int *p=(int*)malloc(4*sizeof(int));p[0]=1;free(p);return 0;}\n"
)

OOB_SRC = (
    "#include <stdlib.h>\n#include <string.h>\n"
    "int main(void){char *p=(char*)malloc(8);memset(p,0,16);free(p);return 0;}\n"
)

CONTRACT_SRC = (
    "//@ requires n <= 4;\n//@ ensures r >= 0;\n"
    "int f(int *a, int n) { return n >= 0 && n <= 4 ? a[n] : 0; }\n"
)

LINT_SRC = (
    "#include <stdint.h>\n"
    "int main(void){intptr_t p = (intptr_t)&p; return 0;}\n"
)

# > 1 MiB source -> myc_request_validate menolak (MYC_ERR_INPUT_TOO_LARGE)
# -> verdict ERROR -> isError=true. Jalan cepat & deterministik untuk
# menguji isError true tanpa menunggu proses eksternal.
HUGE_SRC = "//" + "a" * (1 << 20) + "\n"

# Loop tak hingga -> gate run (--run) menunggu MYC_DEFAULT_TIMEOUT_MS
# (30 dtk) lalu MC_TIMEOUT -> isError=true. Lambat tapi nyata; komentar
# ini menjelaskan kenapa cek isError TIMEOUT butuh ~30 dtk.
LOOP_SRC = "int main(void){for(;;){}return 0;}\n"

# Cek TIMEOUT butuh ~30 dtk; bisa dilewati (untuk iterasi regress cepat)
# dengan MYC_SKIP_SLOW_TIMEOUT=1. Default: dijalankan (bukti isError TIMEOUT).
SKIP_SLOW_TIMEOUT = os.environ.get("MYC_SKIP_SLOW_TIMEOUT") == "1"

# Jumlah cek yang di-skip (counter; maksimal 7: timeout + prove-ok +
# prove-bad + checked-ok + checked-bad + contract-pre + run-stdin; dua
# prove skip bersamaan bila Frama-C/WSL hilang, dua checked skip bersamaan
# bila pola MYC_BUF hilang); dipakai pesan akhir agar konsisten dgn jumlah
# [OK] yang benar2 dijalankan.
SKIPPED_COUNT = 0


def _is_error(result):
    """Baca flag isError dari CallToolResult (SDK 2.x: field is_error)."""
    return bool(getattr(result, "is_error", None) or
                getattr(result, "isError", None))

# Whitelist header konservatif (policy.c) -- harus muncul di output tool
# `policy` beserta jumlahnya. Bila daftar diubah di policy.c, sinkronkan.
EXPECTED_HEADERS = (
    "assert.h", "ctype.h", "errno.h", "float.h", "limits.h",
    "locale.h", "math.h", "stdarg.h", "stdbool.h", "stddef.h",
    "stdint.h", "stdio.h", "stdlib.h", "string.h", "time.h",
)
EXPECTED_HEADER_COUNT = len(EXPECTED_HEADERS)  # 15


def _text(result):
    """Gabungkan content text dari hasil tools/call."""
    out = []
    for c in getattr(result, "content", []) or []:
        if getattr(c, "type", "") == "text":
            out.append(c.text)
    return "\n".join(out)


async def _run(exe):
    # global wajib dideklarasikan SEKALI di awal fungsi sebelum penggunaan
    # apa pun (Python: nama yang di-assign sebelum `global` = SyntaxError).
    global SKIPPED_COUNT
    params = StdioServerParameters(command=exe, args=[], cwd=None)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. tools/list
            listing = await session.list_tools()
            names = [t.name for t in listing.tools]
            expected = {"check", "version", "policy", "contracts", "lint"}
            missing = expected - set(names)
            if missing:
                print("[FAIL] tools/list kurang: %s" % sorted(missing))
                return 1
            print("[OK] tools/list: %s" % ", ".join(names))

            # 2. check (kode aman) -> verdict OK
            r = await session.call_tool("check", arguments={"source": SAFE_SRC})
            t = _text(r)
            if '"verdict":"OK"' not in t:
                print("[FAIL] check OK: %s" % t[:200])
                return 1
            print("[OK] check (aman) -> verdict OK")

            # 3. check --run (OOB) -> RUNTIME_VIOLATION
            r = await session.call_tool(
                "check",
                arguments={"source": OOB_SRC, "flags": ["--run"]})
            t = _text(r)
            if "RUNTIME_VIOLATION" not in t:
                print("[FAIL] check --run: %s" % t[:200])
                return 1
            print("[OK] check --run (OOB) -> RUNTIME_VIOLATION")

            # 4. version
            r = await session.call_tool("version", arguments={})
            t = _text(r)
            # tool_version selalu mencetak baris "myc ", "gcc:", "clang:"
            if "myc " not in t or "gcc:" not in t or "clang:" not in t:
                print("[FAIL] version: %s" % t[:200])
                return 1
            print("[OK] version")

            # 5. policy -- verifikasi jumlah header whitelist
            r = await session.call_tool("policy", arguments={})
            t = _text(r)
            if "whitelist" not in t or \
               "(%d)" % EXPECTED_HEADER_COUNT not in t:
                print("[FAIL] policy (jumlah): %s" % t[:200])
                return 1
            print("[OK] policy (jumlah whitelist = %d)" % EXPECTED_HEADER_COUNT)

            # 5b. policy -- verifikasi seluruh daftar header whitelist
            expected_hdr = ["<%s>" % h for h in EXPECTED_HEADERS]
            missing_hdrs = [h for h in expected_hdr if h not in t]
            if missing_hdrs:
                print("[FAIL] policy kurang header: %s" % missing_hdrs)
                return 1
            print("[OK] policy whitelist: %d header diverifikasi"
                  % len(expected_hdr))

            # 6. contracts
            r = await session.call_tool("contracts",
                                        arguments={"source": CONTRACT_SRC})
            t = _text(r)
            if "requires=1 ensures=1" not in t or "requires n <= 4" not in t:
                print("[FAIL] contracts: %s" % t[:200])
                return 1
            print("[OK] contracts (requires=1 ensures=1)")

            # 7. lint (intptr_t) -> VIOLATION
            r = await session.call_tool("lint", arguments={"source": LINT_SRC})
            t = _text(r)
            if "VIOLATION" not in t:
                print("[FAIL] lint: %s" % t[:200])
                return 1
            print("[OK] lint (intptr_t) -> VIOLATION")

            # 8. contracts -- argumen INVALID (source hilang) -> error -32602
            try:
                await session.call_tool("contracts", arguments={})
                print("[FAIL] contracts tanpa source: tidak error")
                return 1
            except Exception as e:
                # MCPError dari SDK; cari kode JSON-RPC di e.code / e.error.code
                code = getattr(e, "code", None)
                if code is None:
                    code = getattr(getattr(e, "error", None), "code", None)
                if code != -32602:
                    print("[FAIL] contracts tanpa source: code=%r (%r)" % (code, e))
                    return 1
            print("[OK] contracts tanpa source -> JSON-RPC -32602")

            # 9. contracts -- source KOSONG -> hasil valid (bukan error)
            r = await session.call_tool("contracts", arguments={"source": ""})
            t = _text(r)
            if _is_error(r) or "requires=0 ensures=0" not in t:
                print("[FAIL] contracts source kosong: %s" % t[:200])
                return 1
            print("[OK] contracts source kosong -> requires=0 ensures=0 (isError=false)")

            # 10. check -- source > 1 MiB -> verdict ERROR (input_too_large),
            # isError=true. "input_too_large" sudah cukup membuktikan verdict
            # ERROR (nama error hanya muncul pada verdict MC_ERROR).
            r = await session.call_tool("check", arguments={"source": HUGE_SRC})
            t = _text(r)
            if not _is_error(r) or "input_too_large" not in t:
                print("[FAIL] check 1MiB+: isError harus true (verdict ERROR): %s"
                      % t[:200])
                return 1
            print("[OK] check 1MiB+ -> isError=true (verdict ERROR)")

            # 11. check --run -- loop tak hingga -> verdict TIMEOUT, isError=true
            # Catatan: butuh ~MYC_DEFAULT_TIMEOUT_MS (30 dtk) menunggu timeout.
            # Dibungkus asyncio.wait_for(60 dtk) agar test TIDAK menggantung
            # tanpa batas bila timeout server/proc tidak pernah terjadi.
            # Di-lewati (skip) bila MYC_SKIP_SLOW_TIMEOUT=1 utk iterasi cepat.
            if SKIP_SLOW_TIMEOUT:
                SKIPPED_COUNT += 1
                print("[SKIP] check --run loop (TIMEOUT): MYC_SKIP_SLOW_TIMEOUT=1")
            else:
                t0 = time.time()
                try:
                    r = await asyncio.wait_for(
                        session.call_tool(
                            "check",
                            arguments={"source": LOOP_SRC, "flags": ["--run"]}),
                        timeout=60)
                except asyncio.TimeoutError:
                    print("[FAIL] check --run loop: server tidak timeout dalam 60 dtk")
                    return 1
                t = _text(r)
                dt = time.time() - t0
                if not _is_error(r) or "TIMEOUT" not in t:
                    print("[FAIL] check --run loop: isError harus true (TIMEOUT): %s"
                          % t[:200])
                    return 1
                print("[OK] check --run loop -> isError=true (TIMEOUT, %.0f dtk)" % dt)

            # 12. check --driver (fixture ok_driver.c) -> L3 RUNTIME via SDK
            # Membuktikan gate driver-generator D2.2 bisa dipanggil penuh
            # lewat harness MCP resmi (source fixture dikirim sebagai string).
            # Ekspektasi: verdict OK, assurance L3 (RUNTIME), 2 fungsi
            # ber-kontrak diuji, 10 kasus tepi tereksekusi (0 skipped).
            try:
                drv_src = _fixture_source("ok_driver.c")
            except OSError as e:
                print("[FAIL] check --driver: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": drv_src, "flags": ["--driver"]})
            t = _text(r)
            if _is_error(r) or '"verdict":"OK"' not in t or \
               '"assurance":"L3 (RUNTIME)"' not in t:
                print("[FAIL] check --driver: verdict/assurance: %s" % t[:250])
                return 1
            if '"driver_funcs":2' not in t or '"driver_cases":10' not in t:
                print("[FAIL] check --driver: funcs/cases: %s" % t[:250])
                return 1
            print("[OK] check --driver ok_driver.c -> L3 RUNTIME (funcs=2, cases=10)")

            # 13. check --driver (fixture bad_driver_oob.c) -> DRIVER_VIOLATION
            # Fixture ini membaca a[n] dengan n=4 pada kontrak n<=4 -> ASan
            # heap-buffer-overflow pada kasus tepi -> DRIVER_VIOLATION.
            # Catatan: isError=false (pelanggaran dikirim sebagai hasil teks,
            # bukan error MCP -- konsisten dgn check #3 RUNTIME_VIOLATION);
            # driver_cases=0 karena ASan meng-abort sebelum harness sempat
            # mencetak "DRIVER run=N" (ran_driver=true membuktikan gate jalan).
            try:
                bad_drv_src = _fixture_source("bad_driver_oob.c")
            except OSError as e:
                print("[FAIL] check --driver bad: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": bad_drv_src, "flags": ["--driver"]})
            t = _text(r)
            if _is_error(r) or '"verdict":"DRIVER_VIOLATION"' not in t or \
               '"error":"driver_violation"' not in t or \
               '"ran_driver":true' not in t:
                print("[FAIL] check --driver bad: %s" % t[:250])
                return 1
            print("[OK] check --driver bad_driver_oob.c -> DRIVER_VIOLATION")

            # 14. check --prove (fixture ok_prove.c) -> L2 PROVEN bila Frama-C
            # tersedia. Gate prove NON-BLOCKING: bila wsl/frama-c hilang atau
            # Eva tidak menganalisis, ran_prove=false -> [SKIP] (assurance
            # statis dipertahankan, bukan error). Bila berjalan: verdict OK +
            # assurance L2 (PROVEN) + prove_alarms=0 (Eva bersih).
            try:
                prove_src = _fixture_source("ok_prove.c")
            except OSError as e:
                print("[FAIL] check --prove: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": prove_src, "flags": ["--prove"]})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --prove: isError harus false: %s" % t[:250])
                return 1
            if '"ran_prove":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --prove ok_prove.c: gate di-skip "
                      "(Frama-C/WSL tidak tersedia / Eva tidak menganalisis)")
            else:
                if '"verdict":"OK"' not in t or \
                   '"assurance":"L2 (PROVEN)"' not in t or \
                   '"prove_alarms":0' not in t:
                    print("[FAIL] check --prove: verdict/assurance/alarms: %s"
                          % t[:250])
                    return 1
                print("[OK] check --prove ok_prove.c -> L2 PROVEN (alarms=0)")

            # 15. check --prove (fixture bad_prove.c) -> PROVE_VIOLATION bila
            # Frama-C tersedia. Fixture ini membaca OOB via argc opaque sehingga
            # Eva menghasilkan 2 alarm RTE (kelas bug pasti) -> PROVE_VIOLATION.
            # Non-blocking: bila ran_prove=false (Frama-C/WSL hilang / Eva tidak
            # menganalisis) -> [SKIP], bukan [FAIL] (pola sama dgn cek #14).
            try:
                bad_prove_src = _fixture_source("bad_prove.c")
            except OSError as e:
                print("[FAIL] check --prove bad: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": bad_prove_src, "flags": ["--prove"]})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --prove bad: isError harus false: %s" % t[:250])
                return 1
            if '"ran_prove":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --prove bad_prove.c: gate di-skip "
                      "(Frama-C/WSL tidak tersedia / Eva tidak menganalisis)")
            else:
                # Verdict+error membuktikan PROVE_VIOLATION. Jumlah alarm
                # TIDAK di-asert sebagai nilai eksak (bisa beda antar versi
                # Frama-C) -- cukup pastikan > 0 (bukan 0 = Eva bersih).
                if '"verdict":"PROVE_VIOLATION"' not in t or \
                   '"error":"prove_violation"' not in t or \
                   '"prove_alarms":0' in t:
                    print("[FAIL] check --prove bad: verdict/alarms: %s" % t[:250])
                    return 1
                print("[OK] check --prove bad_prove.c -> PROVE_VIOLATION (alarms>0)")

            # 16. check --checked (fixture tests/ok_checked.c) -> L4 SPATIAL
            # bila pola MYC_BUF tersedia. Gate checked NON-BLOCKING: bila
            # source tidak memakai MYC_BUF (ran_checked=false) -> [SKIP].
            # Bila berjalan dan build -DMYC_CHECKED=1 lolos (fat-pointer
            # berlaku) -> checked_build_ok=true + assurance L4 (SPATIAL).
            try:
                checked_src = _tests_source("ok_checked.c")
            except OSError as e:
                print("[FAIL] check --checked: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": checked_src, "flags": ["--checked"]})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --checked: isError harus false: %s" % t[:250])
                return 1
            if '"ran_checked":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --checked ok_checked.c: tanpa pola MYC_BUF "
                      "(gate di-skip)")
            else:
                if '"verdict":"OK"' not in t or \
                   '"assurance":"L4 (SPATIAL)"' not in t or \
                   '"checked_build_ok":true' not in t or \
                   '"checked_uses_buf":true' not in t:
                    print("[FAIL] check --checked: verdict/assurance: %s" % t[:250])
                    return 1
                print("[OK] check --checked ok_checked.c -> L4 SPATIAL "
                      "(checked_build_ok=true)")

            # 17. check --run (fixture bad_contract_pre.c) -> RUNTIME_VIOLATION
            # Fixture P7 (D1.5): fungsi ber-kontrak //@ requires n > 0 yang
            # DIPANGGIL dgn pelanggaran pre (twice(-1)). Gate run meng-inject
            # assert(requires) ke verification build -> assertion failure ->
            # marker "Assertion failed" -> RUNTIME_VIOLATION. Ini membuktikan
            # defense-in-depth kontrak berjalan lewat SDK. Non-blocking: bila
            # ran_runtime=false (clang hilang / build gagal) -> [SKIP].
            try:
                cpre_src = _fixture_source("bad_contract_pre.c")
            except OSError as e:
                print("[FAIL] check --run contract: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": cpre_src, "flags": ["--run"]})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --run contract: isError harus false: %s" % t[:250])
                return 1
            if '"ran_runtime":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --run contract: gate di-skip "
                      "(clang tidak tersedia / build verifikasi gagal)")
            else:
                if '"verdict":"RUNTIME_VIOLATION"' not in t or \
                   '"error":"runtime_violation"' not in t or \
                   '"contract_requires":1' not in t or \
                   "Assertion failed" not in t:
                    print("[FAIL] check --run contract: verdict/assert: %s" % t[:250])
                    return 1
                print("[OK] check --run bad_contract_pre.c -> RUNTIME_VIOLATION "
                      "(assert requires)")

            # 18. check --run + run_stdin (fixture ok_run_stdin.c) -> L3 RUNTIME
            # Fixture membaca stdin dan menggema ke stdout. Argumen run_stdin
            # pada tool MCP `check` (string) harus diteruskan ke stdin program
            # verification -> stdout program berisi "got:<input>". Ini
            # membuktikan channel stdin --run berfungsi penuh lewat SDK resmi.
            # Non-blocking: bila ran_runtime=false (clang hilang / build gagal)
            # -> [SKIP].
            try:
                stdin_src = _fixture_source("ok_run_stdin.c")
            except OSError as e:
                print("[FAIL] check --run stdin: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": stdin_src, "flags": ["--run"],
                           "run_stdin": "halo myc\n"})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --run stdin: isError harus false: %s" % t[:250])
                return 1
            if '"ran_runtime":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --run stdin: gate di-skip "
                      "(clang tidak tersedia / build verifikasi gagal)")
            else:
                if '"verdict":"OK"' not in t or \
                   '"assurance":"L3 (RUNTIME)"' not in t or \
                   "got:halo myc" not in t:
                    print("[FAIL] check --run stdin: verdict/stdout: %s" % t[:250])
                    return 1
                print("[OK] check --run stdin ok_run_stdin.c -> L3 RUNTIME "
                      "(run_stdin echo)")

            # 19. check --checked (fixture tests/bad_checked.c) -> COMPILE_ERROR
            # Fixture P8 (D1.2): memakai MYC_BUF TAPI mengakses b[i] langsung
            # (bukan MYC_AT). Di checked build (-DMYC_CHECKED) fat-struct tidak
            # bisa di-index -> COMPILE_ERROR. Inilah mekanisme L4: akses
            # langsung pada buffer MYC_BUF dipaksa gagal, sehingga semua akses
            # ter-cover MYC_AT. Non-blocking: bila ran_checked=false (tanpa
            # pola MYC_BUF / gate di-skip) -> [SKIP].
            try:
                bad_checked_src = _tests_source("bad_checked.c")
            except OSError as e:
                print("[FAIL] check --checked bad: fixture tak terbaca: %r" % e)
                return 1
            r = await session.call_tool(
                "check",
                arguments={"source": bad_checked_src, "flags": ["--checked"]})
            t = _text(r)
            if _is_error(r):
                print("[FAIL] check --checked bad: isError harus false: %s" % t[:250])
                return 1
            if '"ran_checked":false' in t:
                SKIPPED_COUNT += 1
                print("[SKIP] check --checked bad_checked.c: gate di-skip "
                      "(tanpa pola MYC_BUF / infra hilang)")
            else:
                if '"verdict":"COMPILE_ERROR"' not in t or \
                   '"checked_uses_buf":true' not in t or \
                   '"checked_build_ok":false' not in t:
                    print("[FAIL] check --checked bad: verdict/build_ok: %s" % t[:250])
                    return 1
                print("[OK] check --checked bad_checked.c -> COMPILE_ERROR "
                      "(akses langsung dipaksa gagal)")

            return 0


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else _exe_default()
    exe = os.path.abspath(exe)
    if not os.path.exists(exe):
        print("[FAIL] mcp.exe tidak ditemukan: %s" % exe)
        return 1
    try:
        rc = asyncio.run(_run(exe))
    except Exception as e:
        print("[FAIL] interop SDK gagal: %r" % e)
        return 1
    if rc == 0:
        n_checks = 20 - SKIPPED_COUNT
        suffix = " (%d skip)" % SKIPPED_COUNT if SKIPPED_COUNT else ""
        print("[OK] interop SDK MCP resmi lulus (5 tool, %d cek%s)"
              % (n_checks, suffix))
    return rc


if __name__ == "__main__":
    sys.exit(main())
