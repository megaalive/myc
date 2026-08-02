/*
 * negative_dev.c -- Fixture Negative-Space Analysis (9.8, --negative).
 * 4 dari 5 callsite malloc memeriksa hasil; make_e() MENYIMPANG (hasil
 * dipakai langsung tanpa cek NULL). Gate negative -> COMPLETED_OBSERVATIONS
 * + diagnostic konvensi (confidence), TAPI verdict tetap OK -- observasi
 * heuristik, bukan finding terkonfirmasi (prinsip MYC-AUDIT-014).
 */
#include <stdlib.h>

static char *make_a(void)
{
    char *p = (char *)malloc(4);
    if (p == NULL)
        return NULL;
    return p;
}

static char *make_b(void)
{
    char *p = (char *)malloc(8);
    if (!p)
        return NULL;
    return p;
}

static char *make_c(void)
{
    char *p = (char *)malloc(12);
    if (p != NULL)
        return p;
    return NULL;
}

static char *make_d(void)
{
    char *p = (char *)malloc(16);
    if (!p)
        return NULL;
    return p;
}

/* Menyimpang dari konvensi proyek: hasil malloc dipakai tanpa cek NULL. */
static char *make_e(void)
{
    char *p = (char *)malloc(20);
    p[0] = 'x';
    p[19] = '\0';
    return p;
}

int main(void)
{
    char *a = make_a();
    char *b = make_b();
    char *c = make_c();
    char *d = make_d();
    char *e = make_e();

    free(a);
    free(b);
    free(c);
    free(d);
    free(e);
    return 0;
}
