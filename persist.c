/*
 * persist.c -- Atomic .myc state writes (Batch PR-012, P3-T03).
 *
 * Protokol penulisan atomik untuk semua state `.myc` (*.json):
 *   1. tulis ke file temp DI DIREKTORI YANG SAMA (`<path>.tmp.<pid>`
 *      — pid mencegah dua proses menimpa temp satu sama lain);
 *   2. flush (fflush) + fsync (POSIX) / _commit ~ FlushFileBuffers
 *      (Windows) supaya data benar-benar sampai ke disk;
 *   3. replace atomik: POSIX `rename()` (atomik di filesystem yang sama)
 *      / Windows `MoveFileExA(MOVEFILE_REPLACE_EXISTING |
 *      MOVEFILE_WRITE_THROUGH)` — `rename()` Windows TIDAK menimpa
 *      target yang ada, jadi wajib MoveFileExA;
 *   4. optional parent-dir fsync pada POSIX (best-effort).
 *
 * Pada kegagalan langkah mana pun: temp dibersihkan, target TIDAK
 * disentuh (OLD valid tetap utuh). Pada sukses: target = NEW valid.
 * Crash kapan pun -> target selalu OLD valid ATAU NEW valid (P3-T03).
 *
 * NON-blocking: return 1 sukses / 0 gagal; caller boleh mengabaikan
 * (tidak pernah menurunkan verdict — pola state .myc yang lain).
 *//* MYC-AUDIT-052: glibc hanya mengekspos fileno() di bawah _POSIX_C_SOURCE;
 * -std=c11 menonaktifkan extension (pola sama spt proc.c / proc_fixture.c).
 * Tanpa ini `fsync(fileno(f))` = implicit declaration -> COMPILE_ERROR di
 * Linux (CI self-dogfood persist.c FAIL). */
#define _POSIX_C_SOURCE 200809L
#include "persist.h"
#include "alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#define PERSIST_PID() ((long)_getpid())
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#define PERSIST_PID() ((long)getpid())
#endif

/* Direktori induk dari path (string statis dalam buffer caller). */
#if !defined(_WIN32)
static void persist_dirname(const char *path, char *out, size_t cap)
{
    const char *slash;

    if (!path || !out || cap == 0) {
        if (out && cap > 0)
            out[0] = '\0';
        return;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        out[0] = '.';
        if (cap > 1)
            out[1] = '\0';
        return;
    }
    {
        size_t n = (size_t)(slash - path);
        if (n >= cap)
            n = cap - 1;
        memcpy(out, path, n);
        out[n] = '\0';
    }
}

/* Sync direktori induk (POSIX). Best-effort: error diabaikan. */
static void persist_fsync_parent(const char *path)
{
    char dir[1024];
    int  dfd;

    persist_dirname(path, dir, sizeof(dir));
    dfd = open(dir, O_RDONLY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        (void)close(dfd);
    }
}
#endif /* !_WIN32 */

/* Bersihkan temp STALE (sisa crash) `<path>.tmp.*` di direktori yang
 * sama, termasuk milik PID lain yang sudah mati. Dipanggil sebelum
 * menulis temp baru: crash sebelumnya tidak boleh menumpuk sampah di
 * .myc selamanya (P3-T03 "simulated termination" hygiene).
 * Best-effort: error enumerasi diabaikan; file yang cocok prefix DIHAPUS
 * (remove hanya file, direktori gagal diam-diam). Concurrency window
 * (proses lain sedang menulis temp yang sama) = lost update, bukan
 * korupsi — penanganan locking penuh di luar scope batch ini (pola
 * plan: "do not rely on renames to solve concurrent lost updates"). */
static void persist_cleanup_stale(const char *path)
{
    size_t plen = strlen(path);

    if (plen == 0 || plen > 4000)
        return;
    /* Buffer: dir/base ≤ 511 (dl < sizeof(dir) dijamin return), d_name
     * ≤ NAME_MAX (255), jadi full 1400 aman untuk path lengkap. */
#if defined(_WIN32)
    {
        char dir[512];
        char base[512];
        char full[1400];
        WIN32_FIND_DATAA fd;
        HANDLE h;
        const char *slash;
        size_t dl, base_len;

        /* <dir>\<base> — separator terakhir. */
        slash = strrchr(path, '/');
        if (!slash)
            slash = strrchr(path, '\\');
        if (slash) {
            dl = (size_t)(slash - path);
            if (dl >= sizeof(dir))
                return;
            memcpy(dir, path, dl);
            dir[dl] = '\0';
            snprintf(base, sizeof(base), "%s", slash + 1);
        } else {
            snprintf(dir, sizeof(dir), ".");
            snprintf(base, sizeof(base), "%s", path);
        }
        base_len = strlen(base);
        /* pattern FindFirstFileA: <dir>\<base>.tmp.* */
        snprintf(full, sizeof(full), "%s\\%s.tmp.*", dir, base);
        h = FindFirstFileA(full, &fd);
        if (h == INVALID_HANDLE_VALUE)
            return;
        do {
            if (strncmp(fd.cFileName, base, base_len) != 0)
                continue;
            if (strncmp(fd.cFileName + base_len, ".tmp.", 5) != 0)
                continue;
            snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
            (void)DeleteFileA(full);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    {
        char dir[512];
        char base[512];
        char full[1400];
        DIR *d;
        struct dirent *de;
        const char *slash = strrchr(path, '/');
        size_t base_len;

        if (slash) {
            size_t dl = (size_t)(slash - path);
            if (dl >= sizeof(dir))
                return;
            memcpy(dir, path, dl);
            dir[dl] = '\0';
            snprintf(base, sizeof(base), "%s", slash + 1);
        } else {
            snprintf(dir, sizeof(dir), ".");
            snprintf(base, sizeof(base), "%s", path);
        }
        base_len = strlen(base);
        d = opendir(dir);
        if (!d)
            return;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, base, base_len) != 0)
                continue;
            if (strncmp(de->d_name + base_len, ".tmp.", 5) != 0)
                continue;
            snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
            (void)remove(full);
        }
        closedir(d);
    }
#endif
}

int myc_persist_atomic_write(const char *path, const char *data, size_t len)
{
    char  *tmp;
    size_t plen;
    FILE  *f;

    if (!path || !path[0] || (!data && len > 0))
        return 0;

    plen = strlen(path);
    if (plen > 4096)          /* guard absurd; path state selalu pendek */
        return 0;

    /* temp di direktori yang sama: rename/ReplaceFile baru atomik bila
     * sumber dan target satu filesystem. Suffix pid mencegah dua proses
     * (dua agent harness) menimpa temp satu sama lain. */
    /* bersihkan temp stale dari crash sebelumnya (termasuk PID lain). */
    persist_cleanup_stale(path);

    tmp = (char *)myc_malloc(plen + 64);
    if (!tmp)
        return 0;
    snprintf(tmp, plen + 64, "%s.tmp.%ld", path, (long)PERSIST_PID());

    f = fopen(tmp, "wb");
    if (!f)
        goto cleanup;

    if (len > 0 && fwrite(data, 1, len, f) != len)
        goto fail;
    if (fflush(f) != 0)
        goto fail;
#if defined(_WIN32)
    /* _commit == FlushFileBuffers (CRT -> OS -> disk). */
    if (_commit(_fileno(f)) != 0)
        goto fail;
#else
    if (fsync(fileno(f)) != 0)
        goto fail;
#endif
    if (fclose(f) != 0) {
        f = NULL;
        goto fail_remove;
    }
    f = NULL;

#if defined(_WIN32)
    /* rename() Windows TIDAK menimpa target yang ada; MoveFileExA dengan
     * REPLACE_EXISTING + WRITE_THROUGH = replace atomik + flushed. */
    if (!MoveFileExA(tmp, path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        goto fail_remove;
#else
    if (rename(tmp, path) != 0)
        goto fail_remove;
    persist_fsync_parent(path);
#endif

    myc_free(tmp);
    return 1;

fail:
    if (f)
        fclose(f);
    goto fail_remove;
fail_remove:
    remove(tmp);
    goto cleanup;
cleanup:
    myc_free(tmp);
    return 0;
}

int myc_persist_atomic_write_str(const char *path, const char *str)
{
    if (!str)
        return 0;
    return myc_persist_atomic_write(path, str, strlen(str));
}
