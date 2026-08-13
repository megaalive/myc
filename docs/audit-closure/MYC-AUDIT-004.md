# MYC-AUDIT-004 closure

Status: **CLOSED di kode** — fix terverifikasi + regresi reducer BARU
(PR-003, `test/reducer_exhaustive.c` 1728 checks OK lokal, 2026-08-12);
penutupan issue GitHub menyusul setelah CI membawa regresi ini
(persyaratan PR-004: close only after CI carries the regression).

Catatan proses PR-004: reproduksi terhadap commit lama + pembuktian
kegagalan + reproduksi terhadap HEAD tidak dijalankan ulang di batch ini
(tanpa checkout historis); bukti = root cause terdokumentasi + fixing
commit + regression test yang sudah ada dan terverifikasi lokal.
Referensi: `docs/myc-serious-review-and-roadmap.md` (baris MYC-AUDIT-004),
`docs/audit-history.md` (entri "Silence Is a Finding (9.10)" 2026-08-02),
`docs/verdict-state-inventory.md`, `test/reducer_exhaustive.c`.

## Root cause

Gate runtime/backend yang **diminta** tetapi tidak tersedia (backend
hilang, build gagal, timeout, hasil tidak lengkap) sebelumnya berstatus
`NOT_APPLICABLE` → **diam-diam lolos tanpa debt** → `myc_reduce_verdict()`
tidak melihat incomplete → **verdict tetap `OK`** padahal assurance yang
diminta tidak pernah diberikan (false sense of safety).

## Trigger

`myc check x.c --filc` / `--prove` / `--driver` di sistem tanpa backend
tersebut; `--run` ketika canary/backend gagal.

## Impact on trust

**Melanggar INV-001 (no evidence → no clean claim).** Hasil `OK` saat
gate wajib tidak berjalan membuat agent/harness mengompresinya menjadi
"verification passed" — justru kasus yang paling berbahaya untuk
verifier agent-generated C.

## Affected versions

Semua build sebelum commit `71d297c` (2026-08-02, "feat(9.10): Silence Is
a Finding - --require-complete + kode MYC-INCOMPLETE").

## Fix

Commit `71d297c` (prasyarat AUDIT-004/010 sekaligus diperbaiki):
- Gate diminta + backend tak tersedia → status `UNAVAILABLE` + debt
  (`filc`/`prove` skip → UNAVAILABLE; `driver` tanpa fungsi ber-kontrak
  tetap `NOT_APPLICABLE` = benar-benar tidak berlaku);
- `myc_build_debt()` (gate.c) → kode `MYC-INCOMPLETE-GATE-*`;
- `--require-complete` (`enforce_require_complete` di myc.c) menaikkan
  `OK` → `INCONCLUSIVE` (exit 1);
- Penguatan lanjutan: MYC-AUDIT-040 (RAW-BUFFERS), MYC-AUDIT-041
  (INFRA-FAILED dipertahankan — tidak ditimpa jadi UNAVAILABLE),
  MYC-AUDIT-042 (debt text di-replay identik).

## Regression test

- **BARU (PR-003):** `test/reducer_exhaustive.c` — INV-001: untuk TIAP gate
  kritis (compile/analyzer/runtime/prove/checked/driver/filc) × tiap status
  no-evidence (`UNAVAILABLE`/`INFRA_FAILED`/`INCONCLUSIVE`): verdict harus
  `INCONCLUSIVE` (TIDAK pernah OK) + completeness `INCOMPLETE` + debt
  sesuai tipe. Dijalankan `test/_audit018.sh` + `_regress_run.bat` + CI.
- `test/_regress_run.bat`: blok 9.10/4a — `ok_filc --filc` tanpa Fil-C →
  `MYC-INCOMPLETE-GATE-UNAVAILABLE` + INCONCLUSIVE dengan
  `--require-complete`; `driver_zero_cases` → debt NONZERO-CASES;
  `ok_contract` → gap ensures-unproved terlihat.
- `test/_ci_linux.sh` blok 4a (Linux) — termasuk blok 4a2 INFRA-FAILED
  (MYC-AUDIT-041) dengan fake filc-clang.

## Why the regression cannot silently pass

Test reducer **langsung** memanggil `myc_reduce_verdict()` pada kombinasi
status; bila gate requested + UNAVAILABLE direduksi menjadi OK (regresi
AUDIT-004), assert INV-001 `res.verdict == MC_INCONCLUSIVE` **gagal
seketika** — tidak bergantung pada keberadaan backend atau env CI.
Regresi pipeline menutup sisi wiring (debt + require-complete + replay).

## Residual risk

Enforcement post-reducer (`require-complete`/budget/assumptions) mem-flip
verdict di luar reducer (dokumentasi: `docs/verdict-state-inventory.md`
§1c) — flip tersebut diuji oleh blok regresi terpisah; P2-T01
(trust_negative class) akan mengunci "infrastructure failure ≠ clean
evidence" sebagai kelas CI tersendiri.
