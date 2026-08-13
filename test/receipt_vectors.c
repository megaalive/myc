/*
 * receipt_vectors.c -- PR-014 (MYC-AUDIT-046): canonical test vectors untuk
 * receipt_sha256.
 *
 * Membekukan kanonikal receipt STRING (docs/receipt-canonical.md) — byte-
 * string yang di-hash oleh myc_build_receipt (gate.c) — dengan EMPAT
 * lapis pertahanan independen:
 *
 *   (a) GOLDEN VECTOR V1-V4: string kanonik + sha256 hex di-HARDCODE,
 *       dihitung INDEPENDEN (python3 hashlib, bukan sha256.c myc).
 *       Mengubah format kanonik / enum mapping / urutan append = test
 *       langsung gagal, bukan menunggu laporan.
 *   (b) implementasi REFERENSI di dalam test ini (ditulis dari spec doc,
 *       bukan salinan gate.c) yang WAJIB menghasilkan byte-string sama
 *       dengan myc_receipt_canonical() — perubahan tak sengaja di kedua
 *       sisi tetap tertangkap golden (a).
 *   (c) konsistensi pipeline: res.receipt_sha256 hasil myc_reduce_verdict
 *       HARUS sama dengan sha256(kononikal string) == golden.
 *   (d) properti: determinisme (build sama 2x = hash sama), sensitivitas
 *       komponen demi komponen (fingerprint / source_sha / gate status /
 *       gate id / urutan insert gate / jumlah gate => hash BERUBAH),
 *       rebuild manual (myc_rebuild_receipt), dan truncation buffer
 *       (cap-1 byte + NUL, deterministik, identik dengan yang di-hash).
 *
 * Build (sama dengan cache_corrupt, butuh seluruh pipeline karena myc.c):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o receipt_vectors receipt_vectors.c $SRCS
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "gate.h"
#include "sha256.h"

static int g_fail = 0;
static int g_ok = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

/* ================================================================== */
/* Golden vector (dihitung independen via python3 hashlib)             */
/* ================================================================== */

#define V1_CANON "myc.receipt.v1|OK|complete|debt=fp=|sha=|"
#define V1_SHA   "d5c6ba36e3af0bc27b9b473d7b8279fdd9eb44582d52dc9e73dd128ce8d540af"

#define V2_CANON "myc.receipt.v1|OK|complete|1:completed_clean|debt=fp=|sha=|"
#define V2_SHA   "90f951f64bed6cc4725508db8da95629b7f680937a5b1fa28caaebff926dcfd7"

#define V3_CANON "myc.receipt.v1|INCONCLUSIVE|incomplete|1:completed_clean|" \
                 "3:unavailable|debt=unavailable|fp=|sha=|"
#define V3_SHA   "79db943e82fdbd4bd6b6295b016fc85aeb843a71289e5ff5f8202b9632796eb0"

#define V4_CANON "myc.receipt.v1|INCONCLUSIVE|incomplete|1:completed_clean|" \
                 "4:unavailable|debt=unavailable|fp=fp-1234|" \
                 "sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|"
#define V4_SHA   "3972bd39e3bb976351dd6b7a72c5738292a1b6d3438c5ea2d651e298c4111b8d"

/* ================================================================== */
/* Referensi independen (ditulis dari docs/receipt-canonical.md)       */
/* ================================================================== */

static const char *ref_verdict(myc_verdict v)
{
    switch (v) {
    case MC_OK: return "OK";
    case MC_INCONCLUSIVE: return "INCONCLUSIVE";
    case MC_VIOLATION: return "VIOLATION";
    case MC_COMPILE_ERROR: return "COMPILE_ERROR";
    case MC_ERROR: return "ERROR";
    case MC_TIMEOUT: return "TIMEOUT";
    case MC_CANCELLED: return "CANCELLED";
    case MC_RUNTIME_VIOLATION: return "RUNTIME_VIOLATION";
    case MC_PROVE_VIOLATION: return "PROVE_VIOLATION";
    case MC_FILC_VIOLATION: return "FILC_VIOLATION";
    case MC_DRIVER_VIOLATION: return "DRIVER_VIOLATION";
    }
    return "UNKNOWN";
}

static const char *ref_complete(myc_completeness c)
{
    switch (c) {
    case MYC_COMPLETENESS_COMPLETE: return "complete";
    case MYC_COMPLETENESS_INCOMPLETE: return "incomplete";
    case MYC_COMPLETENESS_UNKNOWN: return "unknown";
    }
    return "unknown";
}

static const char *ref_gate_status(myc_gate_status s)
{
    switch (s) {
    case MYC_GATE_NOT_REQUESTED: return "not_requested";
    case MYC_GATE_NOT_APPLICABLE: return "not_applicable";
    case MYC_GATE_UNAVAILABLE: return "unavailable";
    case MYC_GATE_INFRA_FAILED: return "infra_failed";
    case MYC_GATE_INCONCLUSIVE: return "inconclusive";
    case MYC_GATE_COMPLETED_CLEAN: return "completed_clean";
    case MYC_GATE_COMPLETED_FINDINGS: return "completed_findings";
    case MYC_GATE_COMPLETED_OBSERVATIONS: return "completed_observations";
    }
    return "unknown";
}

static const char *ref_debt_name(myc_debt_type t)
{
    switch (t) {
    case MYC_DEBT_NONE: return "none";
    case MYC_DEBT_GATE_UNAVAILABLE: return "unavailable";
    case MYC_DEBT_GATE_INFRA_FAILED: return "infra_failed";
    case MYC_DEBT_GATE_INCONCLUSIVE: return "inconclusive";
    case MYC_DEBT_NONZERO_CASES: return "nonzero_cases";
    case MYC_DEBT_ENSURES_UNPROVED: return "ensures_unproved";
    case MYC_DEBT_RAW_BUFFERS: return "raw_buffers";
    case MYC_DEBT_OUTPUT_TRUNCATED: return "output_truncated";
    case MYC_DEBT_BUDGET: return "budget_unmet";
    case MYC_DEBT_ASSUMPTION: return "assumption_open";
    case MYC_DEBT_RESOURCE_LIMIT: return "resource_limit";
    case MYC_DEBT_COUNT: return "count";
    }
    return "unknown";
}

/* Append dengan truncation cap-1 + NUL (aturan sama dengan spec doc). */
static void ref_append(char *buf, size_t cap, size_t *off, const char *s)
{
    size_t l = s ? strlen(s) : 0;
    if (*off + l + 1 >= cap)
        l = cap - *off - 1;
    if (l) {
        memcpy(buf + *off, s, l);
        *off += l;
    }
    buf[*off] = '\0';
}

static void ref_canonical(const myc_result *res, char *buf, size_t cap)
{
    size_t off = 0;
    size_t i;
    char gbuf[64];

    if (!res || !buf || cap == 0)
        return;
    buf[0] = '\0';

    ref_append(buf, cap, &off, "myc.receipt.v1|");
    ref_append(buf, cap, &off, ref_verdict(res->verdict));
    ref_append(buf, cap, &off, "|");
    ref_append(buf, cap, &off, ref_complete(res->completeness));
    ref_append(buf, cap, &off, "|");
    for (i = 0; i < res->gate_count; i++) {
        snprintf(gbuf, sizeof(gbuf), "%d:%s|", (int)res->gates[i].id,
                 ref_gate_status(res->gates[i].status));
        ref_append(buf, cap, &off, gbuf);
    }
    ref_append(buf, cap, &off, "debt=");
    for (i = 0; i < res->debt_count; i++) {
        ref_append(buf, cap, &off, ref_debt_name(res->debt[i].type));
        ref_append(buf, cap, &off, "|");
    }
    ref_append(buf, cap, &off, "fp=");
    ref_append(buf, cap, &off, res->fingerprint ? res->fingerprint : "");
    ref_append(buf, cap, &off, "|sha=");
    ref_append(buf, cap, &off, res->source_sha256 ? res->source_sha256 : "");
    ref_append(buf, cap, &off, "|");
}

/* ================================================================== */
/* Builder vector V1-V4                                                */
/* ================================================================== */

static void init_vec(myc_result *res, int vec)
{
    myc_result_init(res);
    switch (vec) {
    case 1:
        break;
    case 2:
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_CLEAN,
                            NULL);
        break;
    case 3:
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_CLEAN,
                            NULL);
        myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_UNAVAILABLE, NULL);
        break;
    case 4:
        res->fingerprint = strdup("fp-1234");
        res->source_sha256 = strdup(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_CLEAN,
                            NULL);
        myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_UNAVAILABLE, NULL);
        break;
    default:
        break;
    }
}

/* Verifikasi penuh satu vector: golden string + golden hash + ref + pipeline. */
static void verify_vec(int vec, const char *canon, const char *golden,
                       const char *label)
{
    myc_result res;
    char c1[4096], c2[4096], sha[65];
    char m[512];

    init_vec(&res, vec);
    myc_reduce_verdict(&res);

    myc_receipt_canonical(&res, c1, sizeof(c1));
    ref_canonical(&res, c2, sizeof(c2));
    sha256_hex(c1, strlen(c1), sha);

    snprintf(m, sizeof(m),
             "%s: canonical == golden string (got '%s' want '%s')",
             label, c1, canon);
    CHECK(strcmp(c1, canon) == 0, m);
    snprintf(m, sizeof(m),
             "%s: referensi independen setuju dengan myc_receipt_canonical",
             label);
    CHECK(strcmp(c2, c1) == 0, m);
    snprintf(m, sizeof(m), "%s: sha256(canonical) == golden hash (got %s)",
             label, sha);
    CHECK(strcmp(sha, golden) == 0, m);
    snprintf(m, sizeof(m), "%s: receipt_sha256 pipeline == golden hash",
             label);
    CHECK(strcmp(res.receipt_sha256, golden) == 0, m);

    myc_result_free(&res);
}

/* ================================================================== */
/* Test                                                                */
/* ================================================================== */

int main(void)
{
    /* ---- T1-T4: golden vector (a)+(b)+(c) ---- */
    verify_vec(1, V1_CANON, V1_SHA, "V1 empty");
    verify_vec(2, V2_CANON, V2_SHA, "V2 clean compile");
    verify_vec(3, V3_CANON, V3_SHA, "V3 mixed + debt");
    verify_vec(4, V4_CANON, V4_SHA, "V4 full feature");

    /* ---- T5: determinisme — build V4 2x = canonical + hash identik ---- */
    {
        myc_result r1, r2;
        char c1[4096], c2[4096];
        init_vec(&r1, 4);
        init_vec(&r2, 4);
        myc_reduce_verdict(&r1);
        myc_reduce_verdict(&r2);
        myc_receipt_canonical(&r1, c1, sizeof(c1));
        myc_receipt_canonical(&r2, c2, sizeof(c2));
        CHECK(strcmp(c1, c2) == 0, "T5: canonical deterministik (build sama)");
        CHECK(strcmp(r1.receipt_sha256, r2.receipt_sha256) == 0,
              "T5: receipt_sha256 deterministik (build sama)");
        myc_result_free(&r1);
        myc_result_free(&r2);
    }

    /* ---- T6: sensitivitas komponen demi komponen (vs V4, hash H4) ---- */
    {
        const char *h4 = V4_SHA;
        const char *vlabel[7] = {
            "s1 fingerprint berbeda",
            "s2 source_sha berbeda",
            "s3 gate status berbeda",
            "s4 gate id berbeda",
            "s5 urutan insert gate",
            "s6 verdict manual + rebuild",
            "s7 jumlah gate berbeda"
        };
        int k;
        for (k = 0; k < 7; k++) {
            myc_result res;
            char c[4096], r[4096], sha[65];
            char m[512];
            myc_result_init(&res);
            switch (k + 1) {
            case 1:
                res.fingerprint = strdup("fp-9999");
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                break;
            case 2:
                res.source_sha256 = strdup(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                break;
            case 3:
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_INCONCLUSIVE, NULL);
                break;
            case 4:
                myc_gate_set_status(&res, MYC_GATE_ANALYZER,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                break;
            case 5:
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                break;
            case 6:
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                break;
            case 7:
                myc_gate_set_status(&res, MYC_GATE_COMPILE,
                                    MYC_GATE_COMPLETED_CLEAN, NULL);
                myc_gate_set_status(&res, MYC_GATE_PROVE,
                                    MYC_GATE_UNAVAILABLE, NULL);
                myc_gate_set_status(&res, MYC_GATE_RUNTIME,
                                    MYC_GATE_UNAVAILABLE, NULL);
                break;
            default:
                break;
            }
            myc_reduce_verdict(&res);
            if (k + 1 == 6) {
                /* s6: hanya verdict diubah manual + rebuild (reducer TIDAK
                 * dijalankan ulang — myc_rebuild_receipt hanya re-hash). */
                res.verdict = MC_TIMEOUT;
                myc_rebuild_receipt(&res);
            }
            myc_receipt_canonical(&res, c, sizeof(c));
            ref_canonical(&res, r, sizeof(r));
            sha256_hex(c, strlen(c), sha);
            snprintf(m, sizeof(m), "%s: hash BERUBAH vs V4 (got %s)",
                     vlabel[k], sha);
            CHECK(strcmp(sha, h4) != 0, m);
            snprintf(m, sizeof(m),
                     "%s: referensi setuju setelah perubahan", vlabel[k]);
            CHECK(strcmp(r, c) == 0, m);
            snprintf(m, sizeof(m),
                     "%s: receipt pipeline konsisten dgn canonical baru",
                     vlabel[k]);
            CHECK(strcmp(res.receipt_sha256, sha) == 0, m);
            myc_result_free(&res);
        }
    }

    /* ---- T7: truncation buffer (cap-1 + NUL, deterministik) ---- */
    {
        myc_result res;
        char big[5001], c1[4096], c2[4096], r1[4096], r2[4096];
        char tiny[16];
        char sha_a[65], sha_b[65];
        size_t i;

        for (i = 0; i < sizeof(big) - 1; i++)
            big[i] = 'x';
        big[sizeof(big) - 1] = '\0';

        myc_result_init(&res);
        res.fingerprint = strdup(big);   /* 5000 byte: melebihi 4095 cap */
        res.source_sha256 = strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        /* tanpa reduce: myc_receipt_canonical murni dari field res. */

        myc_receipt_canonical(&res, c1, sizeof(c1));
        ref_canonical(&res, r1, sizeof(r1));
        CHECK(strlen(c1) == sizeof(c1) - 1,
              "T7: canonical terpotong di cap-1");
        CHECK(strcmp(c1, r1) == 0, "T7: referensi setuju pada truncation");
        CHECK(strncmp(c1, "myc.receipt.v1|ERROR|unknown|debt=fp=", 37) == 0,
              "T7: prefix utuh sebelum truncation");

        /* hash canonical == hash string terpotong (identik yg di-hash) */
        myc_receipt_canonical(&res, c2, sizeof(c2));
        sha256_hex(c1, strlen(c1), sha_a);
        sha256_hex(c2, strlen(c2), sha_b);
        CHECK(strcmp(sha_a, sha_b) == 0,
              "T7: hash deterministik untuk canonical terpotong");
        ref_canonical(&res, r2, sizeof(r2));
        CHECK(strcmp(r2, c1) == 0, "T7: ref truncation identik dgn impl");

        /* cap kecil: cap-1 byte + NUL selalu */
        myc_receipt_canonical(&res, tiny, 1);
        CHECK(strlen(tiny) == 0, "T7: cap=1 -> string kosong (NUL)");
        myc_receipt_canonical(&res, tiny, 5);
        CHECK(strlen(tiny) == 4 && strncmp(tiny, "myc.", 4) == 0,
              "T7: cap=5 -> 4 byte pertama");
        myc_receipt_canonical(&res, tiny, 8);
        CHECK(strlen(tiny) == 7 && strncmp(tiny, "myc.rec", 7) == 0,
              "T7: cap=8 -> 7 byte pertama");
        CHECK(tiny[7] == '\0', "T7: NUL-terminated di cap-1");

        myc_result_free(&res);
    }

    /* ---- T8: myc_rebuild_receipt — re-hash (bukan re-reduce) ---- */
    {
        myc_result res;
        char c[4096], sha[65];

        init_vec(&res, 4);
        myc_reduce_verdict(&res);
        CHECK(strcmp(res.receipt_sha256, V4_SHA) == 0,
              "T8: baseline V4 == golden");
        res.verdict = MC_TIMEOUT;
        myc_rebuild_receipt(&res);
        myc_receipt_canonical(&res, c, sizeof(c));
        sha256_hex(c, strlen(c), sha);
        CHECK(strcmp(res.receipt_sha256, V4_SHA) != 0,
              "T8: verdict berubah -> receipt berubah");
        CHECK(strcmp(res.receipt_sha256, sha) == 0,
              "T8: rebuilt receipt == sha256(canonical baru)");
        myc_result_free(&res);
    }

    /* ---- T9: enum tak dikenal -> fail-closed (INV-011): canonical
     * memakai "unknown"/"UNKNOWN" (bukan crash, bukan clamp) dan
     * referensi setuju. ---- */
    {
        myc_result res;
        char c[4096], r[4096], sha[65];
        char m[512];

        myc_result_init(&res);
        myc_gate_set_status(&res, MYC_GATE_COMPILE, (myc_gate_status)99, NULL);
        myc_reduce_verdict(&res);   /* INV-011: INCONCLUSIVE + debt */
        myc_receipt_canonical(&res, c, sizeof(c));
        ref_canonical(&res, r, sizeof(r));
        sha256_hex(c, strlen(c), sha);
        snprintf(m, sizeof(m), "T9: status di luar enum -> 'unknown' (got '%s')", c);
        CHECK(strstr(c, "1:unknown|") != NULL, m);
        CHECK(strcmp(r, c) == 0, "T9: referensi setuju (unknown status)");
        CHECK(strcmp(sha, V2_SHA) != 0, "T9: hash berbeda dari V2");
        CHECK(strcmp(res.receipt_sha256, sha) == 0,
              "T9: receipt pipeline konsisten (unknown status)");
        myc_result_free(&res);

        /* verdict di luar enum -> "UNKNOWN" (via rebuild manual) */
        myc_result_init(&res);
        myc_gate_set_status(&res, MYC_GATE_COMPILE,
                            MYC_GATE_COMPLETED_CLEAN, NULL);
        myc_reduce_verdict(&res);
        res.verdict = (myc_verdict)42;
        myc_rebuild_receipt(&res);
        myc_receipt_canonical(&res, c, sizeof(c));
        ref_canonical(&res, r, sizeof(r));
        sha256_hex(c, strlen(c), sha);
        snprintf(m, sizeof(m), "T9: verdict di luar enum -> 'UNKNOWN' (got '%s')", c);
        CHECK(strstr(c, "UNKNOWN|") != NULL, m);
        CHECK(strcmp(r, c) == 0, "T9: referensi setuju (unknown verdict)");
        CHECK(strcmp(res.receipt_sha256, sha) == 0,
              "T9: receipt pipeline konsisten (unknown verdict)");
        myc_result_free(&res);
    }

    if (g_fail) {
        printf("receipt_vectors: FAIL (%d fail, %d pass)\n", g_fail, g_ok);
        return 1;
    }
    printf("receipt_vectors: OK (%d checks: golden V1-V4 + determinism/"
           "sensitivity/order/rebuild/truncation)\n", g_ok);
    return 0;
}
