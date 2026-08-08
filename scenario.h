/*
 * scenario.h -- C5: Scenario Packs (--scenario) + D3 auto budget (DS-12).
 *
 * "Resep verifikasi per domain": profil JSON (bukan hardcode logika) yang
 * mengaktifkan sekumpulan gate sekaligus. Skema divalidasi parser ketat
 * json.c. Profil bawaan disimpan sebagai data JSON; user dapat menimpa /
 * menambah via scenarios.json di cwd (atau --scenario-file <path>).
 *
 * D3: `--scenario auto` menebak resep terkecil yang cukup dari struktur
 * source (ada main? ada //@ contract? ada pola firmware?) dan melaporkan
 * "mengapa resep ini" -- assurance tertinggi yang terjangkau tanpa
 * membuang waktu/token pada gate yang tidak informatif.
 *
 * DS-12: scenario juga mendefinisikan DUNIA (environment perturbation
 * contract): stack_budget, no_heap, no_recursion, ... Tercatat di
 * scenario_report dan ditegakkan oleh gate yang diaktifkan (freestanding
 * trap heap, stack gate deteksi rekursi, dst). Verdict tidak pernah
 * berubah hanya karena scenario (semua gate tetap optional, filosofi myc).
 */
#ifndef MYC_SCENARIO_H
#define MYC_SCENARIO_H

#include <stddef.h>

#include "myc.h"

/* Terapkan scenario pack ke request. `name` = "auto" untuk D3 (tebak dari
 * source `src`/`srclen`). `profile_path` = path profil user (NULL = coba
 * scenarios.json di cwd, lalu profil bawaan). Mengisi res->scenario_applied,
 * scenario_name, scenario_auto, scenario_report (arena milik hasil).
 * Return: 0 = OK; -1 = scenario tidak dikenal; -2 = profil file invalid. */
int myc_scenario_apply(myc_request *req, const char *name,
                       const char *src, size_t srclen,
                       const char *profile_path, myc_result *res);

/* `myc scenario list`: daftar semua profil (bawaan + user). */
int myc_scenario_list(const char *profile_path, char *out, size_t cap);

/* `myc scenario info <name>`: detail satu profil. Return 0 = ketemu,
 * -1 = tidak dikenal. */
int myc_scenario_info(const char *name, const char *profile_path,
                      char *out, size_t cap);

#endif /* MYC_SCENARIO_H */
