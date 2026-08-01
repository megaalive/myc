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


def _fixture_path(name):
    """Path file fixture di test/fixtures (relatif ke script ini)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fixtures", name)


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

# Jumlah cek yang di-skip (0/1); dipakai pesan akhir agar konsisten dgn
# jumlah [OK] yang benar-benar dijalankan.
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
                global SKIPPED_COUNT
                SKIPPED_COUNT = 1
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
                drv_src = open(_fixture_path("ok_driver.c"), "rb").read()
                drv_src = drv_src.decode("utf-8", "replace")
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
        n_checks = 13 - SKIPPED_COUNT
        suffix = " (1 skip)" if SKIPPED_COUNT else ""
        print("[OK] interop SDK MCP resmi lulus (5 tool, %d cek%s)"
              % (n_checks, suffix))
    return rc


if __name__ == "__main__":
    sys.exit(main())
