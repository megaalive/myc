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

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("[SKIP] SDK MCP Python tidak terpasang (pip install mcp)")
    sys.exit(2)


def _exe_default():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mcp.exe")


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
        print("[OK] interop SDK MCP resmi lulus (5 tool, 8 cek)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
