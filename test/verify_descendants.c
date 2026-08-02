/* verify_descendants.c -- Regression MYC-AUDIT-011 (POSIX-only).
 *
 * Memverifikasi myc membunuh SELURUH pohon proses (process group) saat
 * timeout, termasuk descendant yang di-fork child -- bukan hanya child
 * langsung.
 *
 * Skema (re-invoke diri sendiri, pola proc_flood.c):
 *   - mode default (harness): jalankan diri sendiri mode "--child" via
 *     myc_proc_run dengan timeout KECIL (2500 ms). Child meng-fork
 *     grandchild lalu tidur 120 s; grandchild menulis pid-nya ke file
 *     "desc.pid", tidur 5 s, lalu menulis "desc.survived" bila MASIH
 *     HIDUP. Harness menunggu 6 s, lalu memastikan "desc.survived"
 *     TIDAK ADA -- bukti kill process group membunuh grandchild juga
 *     (kalau group-kill gagal, grandchild jadi yatim, tertidur 5 s, dan
 *     menulis marker survived).
 *   - mode "--child": fork grandchild; grandchild = pid file + sleep 5 +
 *     marker survived; child sleep 120 s (supaya myc timeout saat child
 *     masih hidup).
 *
 * Catatan: kill(pid,0) tidak dipakai untuk cek kematian karena zombie
 * tetap "ada" di tabel proses (kill(pid,0) sukses). Marker file adalah
 * bukti definitif grandchild benar-benar berhenti mengeksekusi.
 *
 * POSIX-only (fork, sleep): di _audit018.sh dibangun hanya pada sistem
 * POSIX asli (bukan MINGW/MSYS/CYGWIN yang tanpa fork()).
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -o verify_descendants \
 *       verify_descendants.c proc.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#error "verify_descendants adalah POSIX-only (fork, sleep, unistd.h)"
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "myc.h"
#include "proc.h"

#define TIMEOUT_MS 2500   /* myc timeout: child harus masih hidup saat ini;
                               cukup besar agar grandchild sempat menulis
                               desc.pid walau host sibuk, cukup kecil agar
                               test cepat */
#define GRACE_S    6      /* tunggu > sleep grandchild (5 s) untuk marker */

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

static void remove_markers(void)
{
    unlink("desc.pid");
    unlink("desc.survived");
}

/* --- mode child: fork grandchild, lalu tidur 120 s --- */
static void child_descendants(void)
{
    pid_t g = fork();
    if (g == 0) {
        /* === GRANDCHILD === */
        FILE *f = fopen("desc.pid", "w");
        if (f) {
            fprintf(f, "%d\n", (int)getpid());
            fclose(f);
        }
        sleep(5);
        /* Hanya sampai di sini bila TIDAK dibunuh group-kill. */
        f = fopen("desc.survived", "w");
        if (f) {
            fputs("survived\n", f);
            fclose(f);
        }
        _exit(0);
    }
    if (g < 0) {
        fprintf(stderr, "[FAIL] fork grandchild gagal\n");
        _exit(2);
    }
    /* Child tetap hidup lama: myc harus timeout saat child + grandchild
     * masih hidup, lalu membunuh process group. */
    sleep(120);
    _exit(0);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        child_descendants();
        return 2; /* unreachable */
    }

    {
        myc_proc_request preq;
        myc_proc_result  pres;
        const char      *argv2[3];
        FILE            *f;

        remove_markers();
        argv2[0] = argv[0];
        argv2[1] = "--child";
        argv2[2] = NULL;
        memset(&preq, 0, sizeof(preq));
        preq.argv = argv2;
        preq.timeout_ms = TIMEOUT_MS;
        preq.max_output_bytes = 64u * 1024u;
        memset(&pres, 0, sizeof(pres));

        CHECK(myc_proc_run(&preq, &pres) == 0 && pres.timed_out,
              "timeout: myc melaporkan timed_out (dur=%llums)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.err == MYC_ERR_TIMEOUT,
              "timeout: err=MYC_ERR_TIMEOUT");

        /* Grandchild harusnya sudah menulis pid-nya sebelum dibunuh. */
        f = fopen("desc.pid", "r");
        CHECK(f != NULL, "grandchild sempat menulis desc.pid");
        if (f)
            fclose(f);

        /* Tunggu > 5 s: bila grandchild masih hidup (group-kill GAGAL),
         * ia menulis desc.survived. Bila mati, file tidak pernah ada. */
        sleep(GRACE_S);
        f = fopen("desc.survived", "r");
        CHECK(f == NULL,
              "grandchild MATI oleh kill process group (tidak menulis survived)");
        if (f)
            fclose(f);

        myc_proc_result_free(&pres);
        remove_markers();
    }

    printf(g_fail ? "verify_descendants: FAIL (%d)\n"
                  : "verify_descendants: OK (group kill mematikan descendant)\n",
           g_fail);
    return g_fail ? 1 : 0;
}
