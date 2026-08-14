#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_client.py -- Client MCP contoh untuk myc (P9/D2.2).

Menjalankan mcp.exe sebagai server MCP (transport stdio, JSON-RPC 2.0,
satu pesan per baris), melakukan handshake initialize, tools/list, lalu
memanggil tool check / version / contracts / lint.

Usage:
    python mcp_client.py [path_ke_mcp.exe]

Prinsip (sama dengan myc): data hanya lewat stdin/stdout terstruktur;
tidak ada shell string.
"""

import json
import os
import subprocess
import sys

MCP_PROTOCOL = "2024-11-05"


class McpClient:
    def __init__(self, exe):
        self.exe = exe
        # Catatan: bufsize=0 (unbuffered) karena pipe mode binary tidak
        # mendukung line buffering (bufsize=1 memicu RuntimeWarning dan
        # fallback ke buffer default). Dengan bufsize=0, readline() di
        # recv() membaca hingga '\n' tanpa menunggu buffer penuh.
        self.proc = subprocess.Popen(
            [exe],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.next_id = 1

    def send(self, method, params=None):
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        self.next_id += 1
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        return self.recv()

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def recv(self):
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.decode("utf-8"))

    def call_tool(self, name, arguments=None):
        params = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        return self.send("tools/call", params)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.wait(timeout=10)


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "mcp.exe")
    if not os.path.exists(exe):
        print("[FAIL] mcp.exe tidak ditemukan: %s" % exe)
        return 1

    c = McpClient(exe)

    # 1. initialize handshake
    r = c.send("initialize", {
        "protocolVersion": MCP_PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "mcp_client.py", "version": "0.1"},
    })
    if not r or "result" not in r:
        print("[FAIL] initialize:", r)
        c.close()
        return 1
    info = r["result"].get("serverInfo", {})
    print("[OK] initialize: server=%s version=%s protocol=%s" % (
        info.get("name"), info.get("version"),
        r["result"].get("protocolVersion")))

    # 2. notification initialized (tidak dijawab server)
    c.notify("notifications/initialized")

    # 3. tools/list
    r = c.send("tools/list")
    tools = r["result"]["tools"]
    names = [t["name"] for t in tools]
    print("[OK] tools/list: %s" % ", ".join(names))

    # 4. tools/call check (kode aman)
    r = c.call_tool("check", {
        "source": "#include <stdlib.h>\nint main(void){int *p=(int*)malloc(4*sizeof(int));p[0]=1;free(p);return 0;}\n",
    })
    if r and "result" in r:
        text = r["result"]["content"][0]["text"]
        print("[OK] tools/call check:")
        print(text)
    else:
        print("[FAIL] tools/call check:", r)

    # 5. tools/call version
    r = c.call_tool("version")
    if r and "result" in r:
        print("[OK] tools/call version:")
        print(r["result"]["content"][0]["text"].rstrip())
    else:
        print("[FAIL] tools/call version:", r)

    # 6. tools/call contracts
    r = c.call_tool("contracts", {
        "source": "//@ requires n <= 4;\n//@ ensures r >= 0;\nint f(int *a, int n) { return n >= 0 && n <= 4 ? a[n] : 0; }\n",
    })
    if r and "result" in r:
        print("[OK] tools/call contracts:")
        print(r["result"]["content"][0]["text"].rstrip())
    else:
        print("[FAIL] tools/call contracts:", r)

    # 7. tools/call lint (kode berisiko intptr_t -> VIOLATION)
    r = c.call_tool("lint", {
        "source": "#include <stdint.h>\nint main(void){intptr_t p = (intptr_t)&p; return 0;}\n",
    })
    if r and "result" in r:
        print("[OK] tools/call lint:")
        print(r["result"]["content"][0]["text"].rstrip())
    else:
        print("[FAIL] tools/call lint:", r)

    c.close()
    print("[OK] client MCP contoh selesai")
    return 0


if __name__ == "__main__":
    sys.exit(main())
