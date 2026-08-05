# Quickstart

## Build

```
build.bat        # MinGW-w64 / GCC  -> myc.exe, mcp.exe, argv_probe.exe
```

`--run` additionally needs Clang (for ASan/UBSan); `--prove` needs Frama-C;
`--filc` needs Fil-C. All optional.

## Basic check

```
myc check prog.c
```

This runs the static pipeline (preprocess → lint → compile with the memory
tier) and reports a verdict. To read from stdin:

```
cat prog.c | myc check -
```

## Read the result

Use `--json` for machine consumption, or look at the assurance vector:

```
myc check prog.c --json
```

A clean static result looks like `assurance_vector: C1 S1 R0 B0 P0 D0 F0`
(Compile clean, Static clean; Runtime/Checked/Proof/Driver/Filc not run).

## Memory-safe buffers with `MYC_BUF` (→ L4 SPATIAL)

Include `myc_buf.h` and use `MYC_BUF` / `MYC_NEW` / `MYC_AT` / `MYC_FREE`.
Under `gcc -DMYC_CHECKED=1` (the `--checked` gate) every `MYC_BUF` becomes a
fat-pointer struct and **all** accesses must go through `MYC_AT`; a direct
`b[i]` is a compile error. A clean `--checked` build proves all `MYC_AT`
accesses are bounds-checked.

```c
#include <stdio.h>
#include "myc_buf.h"

int main(void) {
    MYC_BUF(int) b;
    MYC_NEW(b, int, 4);
    for (int i = 0; i < 4; i++)
        MYC_AT(b, int, i) = i * 2;   /* only legal access path */
    for (int i = 0; i < 4; i++)
        printf("%d\n", MYC_AT(b, int, i));
    MYC_FREE(b);
    return 0;
}
```

Run it:

```
myc check prog.c --checked
```

> Idiom constraint: keep the `MYC_BUF` variable in **one scope** and never
> assign it to another `MYC_BUF` or pass it to a function — the fat struct is
> anonymous, so two declarations are distinct types. Access it via `MYC_AT`
> (e.g. through a `struct` that *embeds* the `MYC_BUF` member and is passed by
> pointer).

## Runtime verification (→ L3 RUNTIME)

```
myc check prog.c --run
```

Builds with Clang + ASan/UBSan and runs under controlled execution. Clean
(exit 0, no sanitizer report) ⇒ L3 RUNTIME.

```
echo "3 4 + 2 *" | myc check rpn.c --run --run-stdin rpn_input.txt
```

## Contracts + driver / prove

Tag functions with a light contract:

```c
//@ requires n > 0;
int twice(int n) { return n * 2; }
```

- `--driver` generates a harness that calls each contract-tagged function at
  edge cases (bounds of `requires`, 0, 1, 2, 3, …) and runs it under ASan.
- `--prove` runs Frama-C Eva (abstract interpretation) when Frama-C is
  installed.

## In CI

A minimal GitHub Actions step (after building `myc.exe`):

```yaml
- name: Verify generated C
  shell: bash
  run: |
    for f in src/*.c; do
      myc check "$f" --json || exit 1
    done
```

To guard against regressions where myc silently reports OK on broken input,
run the bundled negative guard (Windows):

```
test\_anti_false_ok.bat
```

It fails the build if any known-bad fixture stops producing a negative
verdict.
