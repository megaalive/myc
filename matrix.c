/*
 * matrix.c -- C4: Toolchain Matrix bare metal (portability matrix).
 *
 * "char di ARM tidak sama dengan char di x86". Saat cross-compiler
 * terpasang, source di-cross-compile dan fakta macro target di-dump;
 * hasilnya dibandingkan dengan host: matriks portability yang
 * menunjukkan TARUHAN implementasi-defined mana yang berubah antar
 * target (signedness char, lebar pointer, endianness) + set warning.
 *
 * NON-blocking: semua hasil = observasi (status COMPLETED_OBSERVATIONS);
 * cross-compiler absen = sel di-skip dengan catatan "target lain tidak
 * diuji (host-only)". Verdict tidak pernah turun karena matrix.
 */
#include "matrix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assume.h"
#include "proc.h"

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#define mtx_mkdir(path) _mkdir(path)
#define mtx_getpid()    _getpid()
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define mtx_mkdir(path) mkdir(path, 0700)
#define mtx_getpid()    getpid()
#endif

/* Hitung kemunculan "warning:" pada stderr (set warning). */
static int mtx_count_warnings(const char *txt)
{
    int n = 0;
    const char *p = txt;
    if (!txt)
        return 0;
    while ((p = strstr(p, "warning:")) != NULL) {
        n++;
        p += 8;
    }
    return n;
}

int myc_matrix_gate(const myc_request *req, const char *source,
                    size_t source_len, myc_result *res)
{
    static const char *const targets[] = {
        "arm-none-eabi-gcc",
        "riscv64-unknown-elf-gcc",
        "riscv32-unknown-elf-gcc",
        NULL
    };
    myc_host_facts host;
    char  rep[4096];
    size_t roff = 0;
    int   i, deltas = 0;
    char *gcc_path = NULL;
    char *tmp_dir = NULL;
    char *src_path = NULL, *obj_path = NULL;
    FILE *fsrc = NULL;

    myc_gate_set_status(res, MYC_GATE_MATRIX, MYC_GATE_NOT_APPLICABLE, NULL);
    res->ran_matrix = 1;

    /* 1. fakta host (gcc) */
    gcc_path = myc_find_executable(req->gcc_program ? req->gcc_program
                                                    : "gcc");
    if (!gcc_path) {
        myc_gate_set_status(res, MYC_GATE_MATRIX, MYC_GATE_UNAVAILABLE,
                            "gcc tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_MATRIX, MYC_EVIDENCE_SKIP,
                                "matrix di-skip: gcc hilang");
        return 0;
    }
    memset(&host, 0, sizeof(host));
    myc_assume_fetch_facts(gcc_path, &host);

    roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                             "target matrix (C4/portability):\n"
                             "  host (gcc): char %s, ptr %dB, %s\n",
                             host.char_unsigned ? "unsigned" : "signed",
                             host.ptr_bits,
                             host.little_endian ? "little-endian"
                                                : "big-endian");

    /* 2. per target: facts + compile + delta */
    for (i = 0; targets[i] != NULL; i++) {
        myc_matrix_cell *c = NULL;
        char *cc = myc_find_executable(targets[i]);
        res->matrix_targets++;
        if (!cc) {
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                                     "  %s: TIDAK terpasang (host-only)\n",
                                     targets[i]);
            continue;
        }
        if (res->matrix_ncells < MYC_MATRIX_MAX_CELLS) {
            c = &res->matrix_cells[res->matrix_ncells];
            memset(c, 0, sizeof(*c));
            snprintf(c->target, sizeof(c->target), "%s", targets[i]);
            snprintf(c->cc, sizeof(c->cc), "%s", cc);
            c->available = 1;
            res->matrix_ncells++;
        }
        res->matrix_available++;

        /* 2a. macro facts target (via -dM -E, reuse A1 engine) */
        if (c) {
            myc_host_facts tf;
            memset(&tf, 0, sizeof(tf));
            if (myc_assume_fetch_facts(cc, &tf) == 1) {
                c->facts_ok = 1;
                c->char_unsigned = tf.char_unsigned;
                c->ptr_bits = tf.ptr_bits;
                c->little_endian = tf.little_endian;
            }
        }

        /* 2b. cross-compile -c (observasi warning set) */
        {
            char dirbuf[512];
            int  r;
            myc_proc_request preq;
            myc_proc_result  pres;
            const char *argv_b[12];
            int         narg = 0;
            int         built = 0, nwarn = 0;

            snprintf(dirbuf, sizeof(dirbuf), ".myc_mtx_%d", mtx_getpid());
            tmp_dir = myc_strdup(dirbuf);
            if (!tmp_dir) {
                myc_free(cc);
                res->err = MYC_ERR_INTERNAL;
                goto out;
            }
            mtx_mkdir(tmp_dir);
            r = snprintf(dirbuf, sizeof(dirbuf), "%s/myc_src.c", tmp_dir);
            if (r > 0)
                src_path = myc_strdup(dirbuf);
            r = snprintf(dirbuf, sizeof(dirbuf), "%s/myc_src.o", tmp_dir);
            if (r > 0)
                obj_path = myc_strdup(dirbuf);
            if (!src_path || !obj_path) {
                myc_free(cc);
                res->err = MYC_ERR_INTERNAL;
                goto out;
            }
            fsrc = fopen(src_path, "wb");
            if (!fsrc) {
                myc_free(cc);
                res->err = MYC_ERR_INTERNAL;
                goto out;
            }
            fwrite(source, 1, source_len, fsrc);
            fclose(fsrc);
            fsrc = NULL;

            argv_b[narg++] = cc;
            argv_b[narg++] = "-c";
            argv_b[narg++] = "-O2";
            argv_b[narg++] = "-std=c11";
            argv_b[narg++] = "myc_src.c";
            argv_b[narg++] = "-o";
            argv_b[narg++] = "myc_src.o";
            argv_b[narg] = NULL;
            memset(&preq, 0, sizeof(preq));
            preq.argv = argv_b;
            preq.cwd = tmp_dir;
            preq.timeout_ms = req->timeout_ms;
            preq.max_output_bytes = req->max_output_bytes > 0
                                        ? (size_t)req->max_output_bytes
                                        : MYC_MAX_OUTPUT_BYTES;
            if (myc_proc_run(&preq, &pres)) {
                built = (pres.exit_code == 0);
                nwarn = mtx_count_warnings(pres.stderr_data);
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
            }
            myc_free(src_path);
            src_path = NULL;
            myc_free(obj_path);
            obj_path = NULL;
            myc_free(tmp_dir);
            tmp_dir = NULL;
            if (c) {
                c->built = built;
                c->warnings = nwarn;
            }
            if (built)
                res->matrix_built++;
        }

        /* 2c. delta vs host */
        if (c && c->facts_ok) {
            int cd = 0;
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                                     "  %s: char %s, ptr %dB, %s; compile %s "
                                     "(%d warning)%s\n",
                                     c->target,
                                     c->char_unsigned ? "unsigned"
                                                      : "signed",
                                     c->ptr_bits,
                                     c->little_endian ? "little-endian"
                                                      : "big-endian",
                                     c->built ? "ok" : "GAGAL",
                                     c->warnings,
                                     c->facts_ok ? "" : " (facts tak terbaca)");
            if (c->char_unsigned != host.char_unsigned) {
                cd++;
                roff += (size_t)snprintf(
                    rep + roff, sizeof(rep) - roff,
                    "      -> TARUHAN BERUBAH: char %s di host, %s di %s "
                    "(idiom `c < 0` / `c >= 128` mati)\n",
                    host.char_unsigned ? "unsigned" : "signed",
                    c->char_unsigned ? "unsigned" : "signed", c->target);
            }
            if (host.ptr_bits && c->ptr_bits &&
                c->ptr_bits != host.ptr_bits) {
                cd++;
                roff += (size_t)snprintf(
                    rep + roff, sizeof(rep) - roff,
                    "      -> TARUHAN BERUBAH: sizeof(void*) %dB di host, "
                    "%dB di %s (cast int<->pointer, buffer sizing)\n",
                    host.ptr_bits, c->ptr_bits, c->target);
            }
            if (c->little_endian != host.little_endian) {
                cd++;
                roff += (size_t)snprintf(
                    rep + roff, sizeof(rep) - roff,
                    "      -> TARUHAN BERUBAH: endianness %s di host, %s di "
                    "%s (bit-field, multi-byte parsing)\n",
                    host.little_endian ? "little" : "big",
                    c->little_endian ? "little" : "big", c->target);
            }
            c->deltas = cd;
            deltas += cd;
        }
        myc_free(cc);
    }
    res->matrix_deltas = deltas;

    if (res->matrix_available == 0) {
        roff += (size_t)snprintf(
            rep + roff, sizeof(rep) - roff,
            "\n  TIDAK ada cross-compiler terpasang: target lain TIDAK diuji "
            "(host-only).\n  Pasang arm-none-eabi-gcc / riscv*-unknown-elf-gcc "
            "untuk matriks penuh.\n");
    } else {
        roff += (size_t)snprintf(
            rep + roff, sizeof(rep) - roff,
            "\n  %d target dievaluasi, %d delta asumsi vs host (observasi "
            "portability; NON-blocking)\n",
            res->matrix_available, deltas);
    }

    /* NON-blocking: observasi portability, verdict tidak pernah turun. */
    myc_gate_set_status(res, MYC_GATE_MATRIX,
                        MYC_GATE_COMPLETED_OBSERVATIONS,
                        "target matrix: observasi portability (non-blocking)");
    myc_result_add_evidence(res, MYC_GATE_MATRIX, MYC_EVIDENCE_DIAGNOSTIC,
                            "matrix: portability matrix (observasi)");

    res->matrix_report = myc_result_arena_dup(res, rep, 0);
    myc_free(gcc_path);
    return 0;

out:
    if (fsrc)
        fclose(fsrc);
    if (src_path)
        myc_free(src_path);
    if (obj_path)
        myc_free(obj_path);
    if (tmp_dir)
        myc_free(tmp_dir);
    myc_free(gcc_path);
    myc_gate_set_status(res, MYC_GATE_MATRIX, MYC_GATE_INFRA_FAILED, NULL);
    return 0;
}
