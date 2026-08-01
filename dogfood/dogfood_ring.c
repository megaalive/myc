/*
 * dogfood_ring.c -- Tool dogfooding lintas-program myc (aturan AGENTS.md).
 *
 * Ring buffer byte in-memory (relevan: driver streaming, embedded). Murni
 * API whitelist (stdio/stdlib/string), tanpa system/fopen. Dipakai untuk
 * memastikan jalur OK myc tidak bising dan lint aktif tidak false-positive
 * pada kode sah (malloc+sizeof, memcpy+sizeof, loop aman).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ring {
    unsigned char *buf;
    size_t cap;
    size_t head;
    size_t len;
};

static struct ring ring_create(size_t cap)
{
    struct ring r;
    r.buf = (unsigned char *)malloc(sizeof(unsigned char) * cap);
    r.cap = r.buf ? cap : 0;
    r.head = 0;
    r.len = 0;
    return r;
}

static void ring_free(struct ring *r)
{
    free(r->buf);
    r->buf = NULL;
    r->cap = 0;
}

/* tulis n byte; bila penuh, byte lama tergeser (drop-oldest). */
static void ring_write(struct ring *r, const unsigned char *data, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        size_t pos = (r->head + r->len) % r->cap;
        r->buf[pos] = data[i];
        if (r->len < r->cap)
            r->len++;
        else
            r->head = (r->head + 1) % r->cap;
    }
}

static size_t ring_read(struct ring *r, unsigned char *out, size_t n)
{
    size_t i;
    size_t take = n < r->len ? n : r->len;
    for (i = 0; i < take; i++) {
        out[i] = r->buf[(r->head + i) % r->cap];
    }
    r->head = (r->head + take) % r->cap;
    r->len -= take;
    return take;
}

int main(void)
{
    struct ring r = ring_create(8);
    const unsigned char src[] = "abcdefghij";
    unsigned char out[12];
    size_t got;

    if (r.cap == 0)
        return 1;

    ring_write(&r, src, sizeof(src));
    got = ring_read(&r, out, sizeof(out));
    printf("got=%llu bytes |%.*s|\n",
           (unsigned long long)got, (int)got, (const char *)out);

    ring_free(&r);
    return 0;
}
