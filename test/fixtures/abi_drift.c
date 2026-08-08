/*
 * abi_drift.c -- fixture ABI certificate (Fase 5, SOL-14) versi DRIFT.
 *
 * Perubahan ABI tak diminta vs abi_stable.c (harus terdeteksi delta):
 *   - Point bertambah member `z`        -> size 8 -> 12 (offset/size);
 *   - Mode.MODE_ON berubah 1 -> 2        -> enum value berubah;
 *   - reset(Point*) dihapus              -> symbol hilang;
 *   - scale(float) ditambahkan           -> symbol baru.
 * Pixel/Player/Access/add tetap (tidak boleh muncul di delta).
 */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int x;
    int y;
    int z;              /* DRIFT: member baru */
} Point;

typedef struct {
    uint8_t r, g, b;
} Pixel;

typedef struct {
    char  name[16];
    int   score;
} Player;

typedef enum {
    MODE_OFF = 0,
    MODE_ON = 2         /* DRIFT: nilai berubah */
} Mode;

typedef enum {
    NONE = 0,
    READ = 4,
    WRITE = 8
} Access;

int add(int a, int b)
{
    return a + b;
}

float scale(float v)    /* DRIFT: symbol baru */
{
    return v * 2.0f;
}

static int hidden(int v)
{
    return v * 2;
}

int use_hidden(void)        /* memakai hidden agar fungsi static terpakai */
{
    return hidden(7);
}
