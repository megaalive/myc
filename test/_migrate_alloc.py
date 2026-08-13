#!/usr/bin/env python3
"""Migrate malloc/calloc/realloc/free -> myc_* wrappers in CODE context only.

A C-aware tokenizer: tracks string literals, char literals, line comments,
block comments. Replaces a standalone identifier (malloc/calloc/realloc/free)
with the myc_* wrapper ONLY when it appears in code context (not string/comment)
and is immediately followed by '(' (optionally whitespace).

Usage: python migrate_alloc.py <file...>
"""
import re
import sys


TARGETS = {"malloc": "myc_malloc", "calloc": "myc_calloc",
           "realloc": "myc_realloc", "free": "myc_free"}


def migrate_one(text):
    out = []
    i = 0
    n = len(text)
    state = "CODE"  # CODE | STRING | CHAR | LINE | BLOCK
    count = 0
    while i < n:
        c = text[i]
        if state == "CODE":
            if c == '"':
                state = "STRING"
                out.append(c); i += 1
            elif c == "'":
                state = "CHAR"
                out.append(c); i += 1
            elif c == "/" and i + 1 < n and text[i+1] == "/":
                state = "LINE"
                out.append(c); i += 1
            elif c == "/" and i + 1 < n and text[i+1] == "*":
                state = "BLOCK"
                out.append(c); i += 1
            elif (c.isalpha() or c == "_"):
                # read identifier
                j = i
                while j < n and (text[j].isalnum() or text[j] == "_"):
                    j += 1
                ident = text[i:j]
                # check prefix: previous output char must not be identifier char
                prev_ident = False
                if out and (out[-1].isalnum() or out[-1] == "_"):
                    prev_ident = True
                # member access (x->free / x.free): scan back over whitespace
                # for '.' or '->' in raw text -- those are field accesses, not
                # calls, and must NOT be wrapped.
                member_access = False
                k2 = i - 1
                while k2 >= 0 and text[k2] in " \t":
                    k2 -= 1
                if k2 >= 0 and text[k2] == ".":
                    member_access = True
                if k2 >= 1 and text[k2] == ">" and text[k2-1] == "-":
                    member_access = True
                # skip whitespace after identifier to find '('
                k = j
                while k < n and text[k] in " \t":
                    k += 1
                if (not prev_ident and not member_access and
                        ident in TARGETS and k < n and text[k] == "("):
                    out.append(TARGETS[ident])
                    count += 1
                else:
                    out.append(ident)
                i = j
            else:
                out.append(c); i += 1
        elif state == "STRING":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i+1]); i += 2
            elif c == '"':
                state = "CODE"; i += 1
            else:
                i += 1
        elif state == "CHAR":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i+1]); i += 2
            elif c == "'":
                state = "CODE"; i += 1
            else:
                i += 1
        elif state == "LINE":
            out.append(c)
            if c == "\n":
                state = "CODE"
            i += 1
        elif state == "BLOCK":
            out.append(c)
            if c == "*" and i + 1 < n and text[i+1] == "/":
                out.append("/"); i += 2
                state = "CODE"
            else:
                i += 1
    return "".join(out), count


def main():
    total = 0
    for path in sys.argv[1:]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        new_text, cnt = migrate_one(text)
        if cnt:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new_text)
        total += cnt
        print(f"{path}: {cnt} replacement")
    print(f"TOTAL: {total}")


if __name__ == "__main__":
    main()