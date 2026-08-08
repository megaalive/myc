/*
 * abi_stable.c -- fixture ABI certificate (Fase 5, SOL-14) versi STABIL.
 *
 * Snapshot ABI deterministik: 3 struct (Point, Pixel, Player), 2 enum
 * (Mode, Access), 3 fungsi global (add, reset, use_hidden) + 1 static
 * (hidden yang TIDAK boleh tercatat sebagai symbol exported).
 *
 * Digunakan CI (Linux 6i + Windows) untuk:
 *   - determinisme snapshot (dua run sama);
 *   - delta vs abi_drift.c (layout/enum/symbol berubah).
 */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    uint8_t r, g, b;    /* multi-member per pernyataan */
} Pixel;

typedef struct {
    char  name[16];
    int   score;
} Player;

typedef enum {
    MODE_OFF = 0,
    MODE_ON = 1
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

void reset(Point *p)
{
    p->x = 0;
    p->y = 0;
}

static int hidden(int v)    /* internal: TIDAK boleh jadi symbol ABI */
{
    return v * 2;
}

int use_hidden(void)        /* memakai hidden agar fungsi static terpakai */
{
    return hidden(7);
}
