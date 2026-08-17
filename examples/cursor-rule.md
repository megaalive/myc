# myc — rule singkat untuk coding agent

Repo C yang agen sentuh harus punya `myc.prompt.md` + `myc.spec.json` di
akar proyek (pack; lihat README). Hormati isinya.

Setelah menulis atau mengubah berkas `.c`:

1. Jalankan `myc check FILE.c --lite` (atau MCP tool `verify`).
2. Baca field `action`. Hormati persis:
   - `STOP_COMPILE_CLEAN` — berhenti. Ini compile-clean, **bukan** bukti memory-safe.
   - `FIX_ONE` — sunting **hanya** `allowed_span`. Terapkan `fix_or_null` bila ada; jangan menebak jika null.
   - `ESCALATE_RUNTIME` — `myc check FILE.c --run --lite`
   - `ESCALATE_CONTRACT` — `myc check FILE.c --driver --lite`
   - `GIVE_UP_NO_TEMPLATE` — jangan menebak; `myc context FILE.c --budget 4K`
3. Jangan mengirim daftar flag myc. Jangan `--filc` / `--prove` kecuali `action` eskalasi memintanya.
4. Jangan mengubah kontrak `//@`, sanitizer, atau signature publik.
5. Bila `--watch-diff` dan `action` = `STOP_COMPILE_CLEAN` dengan why
   "fungsi finding tidak berubah": jangan sunting ulang fungsi lain.
