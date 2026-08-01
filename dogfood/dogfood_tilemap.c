/*
 * dogfood_tilemap.c -- Tool dogfooding lintas-program myc (aturan AGENTS.md).
 *
 * Flood-fill BFS pada tile map 2D (relevan: game — pathfinding, area
 * reachability, procedural generation). Murni API whitelist (stdio/stdlib),
 * tanpa system/fopen. Ditulis dan diperiksa dengan myc untuk mematangkan
 * jalur "lolos" (OK) pada kode yang sah.
 *
 * Uji nyata yang melatih myc:
 *   - indeks 2D y*W+x dengan batas eksplisit (bounds analysis: lint +
 *     gcc -Warray-bounds/-fanalyzer harus diam pada kode sah);
 *   - stack eksplisit berkapasitas tetap (BFS non-rekursif -> aman dari
 *     stack overflow; tidak ada realloc -> tidak memicu lint realloc);
 *   - alokasi heap dengan sizeof eksplisit (tidak ada perkalian tanpa
 *     sizeof) + free yang berpasangan;
 *   - penyalinan byte memakai loop eksplisit (bukan memcpy tanpa sizeof);
 *   - `--run` harus L3 RUNTIME (program executable, ASan bersih).
 */
#include <stdio.h>
#include <stdlib.h>

#define MAP_W 16
#define MAP_H 9
#define MAX_CELLS (MAP_W * MAP_H)

/* template peta: '#' = dinding, '.' = lantai (MAP_W char per baris) */
static const char MAP_SRC[MAP_H][MAP_W + 1] = {
    "################",
    "#..............#",
    "#.####.####.####",
    "#....#....#....#",
    "####.####.####.#",
    "#....#....#....#",
    "#.####.####.####",
    "#..............#",
    "################",
};

/* Flood-fill BFS dari (sx,sy): semua sel '.' yang terjangkau ditandai 'F'.
 * Kembalikan jumlah sel terisi; 0 bila start tidak valid. */
static int flood_fill(char *map, int w, int h, int sx, int sy)
{
    int stack_x[MAX_CELLS];
    int stack_y[MAX_CELLS];
    int sp = 0;
    int count = 0;

    if (sx < 0 || sx >= w || sy < 0 || sy >= h)
        return 0;
    if (map[sy * w + sx] != '.')
        return 0;

    stack_x[sp] = sx;
    stack_y[sp] = sy;
    sp = 1;
    map[sy * w + sx] = 'F';
    count = 1;

    while (sp > 0) {
        int x = stack_x[sp - 1];
        int y = stack_y[sp - 1];
        int nx, ny;

        sp--;
        for (ny = y - 1; ny <= y + 1; ny++) {
            for (nx = x - 1; nx <= x + 1; nx++) {
                int idx;
                if ((nx == x) == (ny == y))
                    continue;               /* sel pusat: lewati */
                if (nx < 0 || nx >= w || ny < 0 || ny >= h)
                    continue;
                if (sp >= MAX_CELLS)
                    return count;           /* guard defensif (tak mungkin) */
                idx = ny * w + nx;
                if (map[idx] != '.')
                    continue;
                map[idx] = 'F';
                stack_x[sp] = nx;
                stack_y[sp] = ny;
                sp++;
                count++;
            }
        }
    }
    return count;
}

int main(void)
{
    char *map;
    int   filled;
    int   y, x;

    map = (char *)malloc(MAP_W * MAP_H * sizeof(*map));
    if (!map)
        return 1;
    for (y = 0; y < MAP_H; y++)
        for (x = 0; x < MAP_W; x++)
            map[y * MAP_W + x] = MAP_SRC[y][x];

    filled = flood_fill(map, MAP_W, MAP_H, 1, 1);
    printf("filled=%d\n", filled);

    for (y = 0; y < MAP_H; y++) {
        for (x = 0; x < MAP_W; x++)
            putchar(map[y * MAP_W + x]);
        putchar('\n');
    }

    if (filled <= 0 || map[1 * MAP_W + 1] != 'F') {
        printf("self-check GAGAL\n");
        free(map);
        return 1;
    }
    printf("self-check OK\n");

    free(map);
    return 0;
}
