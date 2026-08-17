# Verdict State Inventory — peta semua mutasi state verdict

> Batch PR-002 dari `myc-production-readiness-plan.md`: laporan lokasi
> SETIAP assignment/konversi dari: verdict, gate status, assurance,
> finding/completeness/claim, debt, dan internal failure (`err`).
> **Tidak ada perubahan perilaku.** Tujuan: basis untuk memastikan
> `myc_reduce_verdict()` (gate.c) adalah **satu-satunya reducer kanonik**
> dan setiap mutasi lain terdokumentasi sebagai procedure verdict / transport
> error yang di-normalisasi ulang oleh reducer.

---

## 1. Verdict (`res->verdict =`)

### 1a. Reducer kanonik (satu-satunya tempat menurunkan verdict AKHIR dari gate status)

| Lokasi | Peran |
|---|---|
| `gate.c` `myc_reduce_verdict()` L554-560 | Hanya mengubah `MC_OK`/`MC_ERROR` → `MC_VIOLATION` (ada FINDINGS) / `MC_INCONCLUSIVE` (ada incomplete) / `MC_OK` (semua clean). Verdict spesifik lain dipertahankan. **Fix PR-003 (2026-08-12):** `default:` branch ditambahkan — status gate tak dikenal (di luar enum) → `has_incomplete` (INV-011 fails closed; sebelumnya jatuh ke `MC_OK`). |

### 1b. Procedure verdict — diset GATE SEBELUM reducer, dipertahankan reducer

Gate set verdict spesifik (transport/backend outcome), lalu memanggil
`myc_reduce_verdict()` yang TIDAK menimpa verdict non-OK/ERROR:

| Modul | Nilai | Makna |
|---|---|---|
| `compile.c` L725,823 | `MC_OK` | compile gate selesai |
| `compile.c` L747,757,873,1080,1157 | `MC_ERROR` | gcc tidak ditemukan / infra |
| `compile.c` L784,800,1015,1113,1165 | `MC_TIMEOUT` | preprocess/compile timeout |
| `compile.c` L810,1032,1129,1178 | `MC_COMPILE_ERROR` | gcc menemukan error |
| `run.c` L699,1186,1682,1686 | `MC_RUNTIME_VIOLATION` | sanitizer finding |
| `run.c` L525,546,612,654,1129,1455 | `MC_TIMEOUT` | run timeout |
| `run.c` L803,1153 | `MC_INCONCLUSIVE` | run tidak lengkap / canary gagal |
| `prove.c` L397,522,553 | `MC_PROVE_VIOLATION` | alarm Eva |
| `prove.c` L277,299,329,351,451,495 | `MC_TIMEOUT` | Eva timeout |
| `prove.c` L544 | `MC_OK` | Eva clean |
| `filc.c` L376,890 | `MC_FILC_VIOLATION` | panic Fil-C |
| `filc.c` L341,354,573,594,660,683,819,854 | `MC_TIMEOUT` | Fil-C timeout |
| `driver.c` L1685,2604,3850 | `MC_DRIVER_VIOLATION` | driver finding |
| `driver.c` L1434,1455,1514,1657,2451,2524,2571 | `MC_TIMEOUT` | driver timeout |

### 1c. Enforcement post-reducer (flip terbatas OK → INCONCLUSIVE)

| Lokasi | Peran |
|---|---|
| `myc.c` L805 (`enforce_require_complete`) | `--require-complete`: gap verifikasi → `MC_INCONCLUSIVE` (hanya dari `MC_OK`) |
| `budget.c` L331-332 | budget contract target tak tercapai → `MC_INCONCLUSIVE` (hanya dari `MC_OK`) |
| `assume.c` L1182-1183 | `--require-assumptions-closed`: asumsi terbuka → `MC_INCONCLUSIVE` (hanya dari `MC_OK`) |

Setelah flip ini receipt dibangun ulang (`myc_rebuild_receipt`), TANPA
menjalankan reducer lagi (reducer bisa membatalkan flip — lihat komentar
gate.c `myc_rebuild_receipt`).

### 1d. Replay / inisialisasi / salinan

| Lokasi | Peran |
|---|---|
| `myc.c` L96 (`myc_result_init`) | `MC_ERROR` (nilai awal; reducer memrosesnya) |
| `cache.c` `cache_apply_entry` | replay: `res->verdict = e->verdict` (hanya bila cache key cocok **dan** `cache_entry_semantic_ok`) |
| `cache.c` `cache_entry_semantic_ok` | verdict/err/gate out-of-range atau state mustahil → karantina, MISS, recompute (PR-013; **bukan** clamp ke `MC_OK`) |
| `agent.c` `myc_agent_result` / capsule | salinan ke output (bukan mutasi hasil) |
| `ledger.c` L330 | salinan string ke ledger |

---

## 2. Gate status (`gate->status =` / `res->gates[]`)

| Lokasi | Peran |
|---|---|
| `gate.c` `myc_gate_set_status()` L47 | **SATU-SATUNYA penulis status gate di pipeline** (membuat/update entry, `requested=1`) |
| `cache.c` L1055 (replay) / L1725 (save) / L421 (parse clamp) / L767 (serialize) | replay/serialisasi typed gate status |
| `compile.c` L1285,1345; `budget.c` L208; `gate.c` L341-342 | pembaca status (tidak menulis) |
| `profile.c` L188,306-310,350 | agregasi observasi (tidak menulis hasil) |

Konversi status → string: `gate.c` `myc_gate_id_short()` /
`rc_gate_status()` (default `"unknown"` = fail-closed).

---

## 3. Assurance / finding / completeness / claim

| Lokasi | Peran |
|---|---|
| `gate.c` reducer L565 | completeness: `has_incomplete ? INCOMPLETE : COMPLETE` |
| `gate.c` reducer L573-577 | finding: FINDINGS > INCONCLUSIVE > CLEAN |
| `gate.c` reducer L582-594 | assurance legacy ladder dari gate clean |
| `gate.c` reducer L601 | `claim_status = myc_validate_claim()` |
| `gate.c` reducer L617 | **downgrade**: hard finding tanpa witness → finding `INCONCLUSIVE` (bukan verdict) |
| `myc.c` L806-809 | require-complete: finding/completeness diselaraskan setelah flip |
| `budget.c` L333-336 | budget: finding/completeness diselaraskan |
| `assume.c` L1184-1187 | assumptions: finding/completeness diselaraskan |
| `compile.c` L1255,1316,1368,1413,1468,1515,1564,1663 | assurance = NONE saat gate error (transport) |
| `cache.c` L1044-1048 (replay) / L1486-1489 (save) / L171-173 (parse clamp) | replay/serialisasi |
| `myc.c` L591 | reset completeness saat reuse |
| `myc.c` L772-774 (capsule), `agent.c` L376-378, `profile.c` L315-335, `transaction.c` L170 | salinan/agregasi (bukan mutasi hasil) |

---

## 4. Debt (`res->debt[]`, `debt_count`)

| Lokasi | Peran |
|---|---|
| `gate.c` `myc_build_debt()` + `myc_debt_add()` L171-177,308-362 | **Sumber kanonik debt dari typed gate status + scope counters** (dipanggil reducer): GATE-UNAVAILABLE / GATE-INFRA-FAILED / GATE-INCONCLUSIVE / NONZERO-CASES / ENSURES-UNPROVED / RAW-BUFFERS / OUTPUT-TRUNCATED |
| `budget.c` L272-317 | `MYC_DEBT_BUDGET` (enforcement) |
| `assume.c` L1168-1176 | `MYC_DEBT_ASSUMPTION` (enforcement) |
| `myc.c` L803 | kondisi require-complete (baca debt) |
| `myc.c` L590 | reset saat reuse |
| `cache.c` L1064-1073 (replay) / L1731-1737 (save) / L437 (parse) | replay/serialisasi (debt text ikut disimpan — MYC-AUDIT-042) |

---

## 5. Internal failure (`res->err =`)

Transport/internal error diset di seluruh adapter (bukan verdict):

- `proc.c` L865-1364: `MYC_ERR_INTERNAL` (pipe/alloc/spawn gagal),
  `MYC_ERR_EXECUTE_FAILED` (spawn), `MYC_ERR_TIMEOUT`,
  `MYC_ERR_INVALID_REQUEST`.
- `compile.c` L396,746,756,1081,1158,1700; `run.c` L433-1683;
  `driver.c` L1357-3735; `prove.c` L278-554; `filc.c` L342-891;
  `stack.c` L380-440; `matrix.c` L139-157; `myc.c` L903,1000.

Aturan umum: `MYC_ERR_INTERNAL` → hasil TIDAK di-cache
(cache.c L1454-1456) dan verdict spesifik dipertahankan (tidak pernah
diubah jadi OK oleh reducer).

Catatan kelengkapan: daftar lokasi `err` untuk `driver.c` dan `run.c`
adalah **ringkasan rentang** (mis. `driver.c L1357-3735`) — berasal dari
pencarian yang di-truncate per file (30 hasil) — bukan enumerasi eksplisit
tiap baris; rentang menutupi situs yang tidak tampil di hasil. Untuk
inventaris penuh per baris, jalankan ulang `grep -n 'res->err =' *.c`
dan sandingkan dengan daftar di atas.

---

## 6. Analisis: satu reducer kanonik?

**Ya, dengan dua pengecualian yang terdokumentasi:**

1. **Procedure verdict (1b)** diset gate sebelum reducer; reducer hanya
   menyatukan status gate dan TIDAK menimpa verdict spesifik — ini desain
   (transport error tidak boleh direinterpretasi reducer).
2. **Enforcement post-reducer (1c)** mem-flip `MC_OK` → `MC_INCONCLUSIVE`
   berdasarkan debt eksternal (require-complete / budget / assumptions);
   flip ini sengaja tidak lewat reducer (reducer akan membatalkannya).

**Satu-satunya path lain yang men-set verdict akhir:** `cache.c` replay
(1d) — aman karena hanya mereplay entry yang key-nya cocok persis, dengan
**gap INV-011** (value verdict korup di luar rentang di-ignore → default
`MC_OK`; target P2/P3 cache corruption policy).

**Kesimpulan untuk PR-003:** reducer sudah terpusat di `gate.c`;
test exhaustif kombinasi status gate = langkah yang benar (bukan refactor).
