/*
 * causal.c -- Causal Finding Graph (Fase 3, SOL-09).
 */
#include "causal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

/* ---------- union-find kecil (cluster) ---------- */

static int uf_find(int *parent, int x)
{
    while (parent[x] != x) {
        parent[x] = parent[parent[x]];   /* path halving */
        x = parent[x];
    }
    return x;
}

static void uf_union(int *parent, int a, int b)
{
    int ra = uf_find(parent, a);
    int rb = uf_find(parent, b);
    if (ra != rb)
        parent[ra] = rb;
}

/* ---------- ekstraksi symbol (identifier dalam kutip gcc 'x') ---------- */

/* Ambil semua identifier dalam kutip tunggal gcc (mis. 'buf', 'p', 'realloc').
 * Ditulis ke out (dipisah koma), batas 48 char per symbol (hardcoded di sini).
 * Return 1 bila ada minimal satu symbol, 0 bila tidak. */
static int extract_symbols(const char *msg, char *out, size_t out_cap)
{
    const char *p = msg;
    size_t o = 0;
    int found = 0;

    if (!msg || out_cap == 0)
        return 0;
    out[0] = '\0';

    while (*p && o + 2 < out_cap) {
        if (*p == '\'') {
            const char *start = p + 1;
            const char *end = start;
            size_t len;
            while (*end && *end != '\'')
                end++;
            len = (size_t)(end - start);
            /* identifier C wajar: huruf/angka/underscore; abaikan simbol
             * operator (mis. '=', '++') dan string kosong. */
            if (len > 0 && len <= 48 &&
                ((start[0] >= 'a' && start[0] <= 'z') ||
                 (start[0] >= 'A' && start[0] <= 'Z') ||
                 start[0] == '_')) {
                size_t i;
                int  valid = 1;
                for (i = 0; i < len; i++) {
                    char c = start[i];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '_')) {
                        valid = 0;
                        break;
                    }
                }
                if (valid) {
                    if (found)
                        out[o++] = ',';
                    if (o + len + 1 >= out_cap)
                        break;
                    memcpy(out + o, start, len);
                    o += len;
                    out[o] = '\0';
                    found = 1;
                }
            }
            p = end;
        }
        p++;
    }
    return found;
}

/* Apakah dua daftar symbol (koma-pisah) punya irisan?
 * Tokenizer lokal (tanpa strtok_r) agar portabel ke -std=c11 ketat:
 * glibc hanya mengekspos strtok_r di bawah _POSIX_C_SOURCE, dan CI
 * Linux memakai -Werror=implicit-function-declaration. */
static int symbols_overlap(const char *a, const char *b)
{
    const char *pa = a;

    if (!a || !b || !a[0] || !b[0])
        return 0;
    while (*pa) {
        const char *ea = strchr(pa, ',');
        size_t la = ea ? (size_t)(ea - pa) : strlen(pa);
        const char *pb = b;
        if (la > 0) {
            while (*pb) {
                const char *eb = strchr(pb, ',');
                size_t lb = eb ? (size_t)(eb - pb) : strlen(pb);
                if (lb > 0 && la == lb && strncmp(pa, pb, la) == 0)
                    return 1;
                if (!eb)
                    break;
                pb = eb + 1;
            }
        }
        if (!ea)
            break;
        pa = ea + 1;
    }
    return 0;
}

/* ---------- root selection ---------- */

/* Pesan GCC dari JSON sering diawali spasi (" note: ...") — skip
 * whitespace agar deteksi note robust. */
static const char *skip_ws(const char *s)
{
    while (s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))
        s++;
    return s;
}

/* Semakin tinggi confidence, semakin mungkin root.
 * Note (pre-state) TIDAK pernah root. */
static int node_rank(const myc_causal_node *n)
{
    return n->is_note ? -1 : (int)n->confidence;
}

void myc_causal_build(const myc_result *res, myc_causal_graph *g)
{
    int parent[MYC_MAX_CAUSAL_NODES];
    int i, j, n;
    int seen[MYC_MAX_CAUSAL_NODES];

    if (!res || !g)
        return;
    memset(g, 0, sizeof(*g));

    n = res->diag_count;
    if (n > MYC_MAX_CAUSAL_NODES)
        n = MYC_MAX_CAUSAL_NODES;

    for (i = 0; i < n; i++) {
        myc_causal_node *nd = &g->nodes[g->count];
        const myc_diagnostic *d = &res->diags[i];
        char syms[512];

        nd->diag_index = i;
        nd->line = d->line;
        nd->col = d->col;
        nd->confidence = d->confidence;
        nd->is_note = d->message &&
                      strncmp(skip_ws(d->message), "note:", 5) == 0;
        if (extract_symbols(d->message, syms, sizeof(syms)))
            nd->symbols = myc_strdup(syms);
        else
            nd->symbols = NULL;
        parent[g->count] = g->count;
        g->count++;
    }

    /* Cluster: symbol sama ATAU lokasi sama ATAU witness overlap. */
    for (i = 0; i < g->count; i++) {
        for (j = i + 1; j < g->count; j++) {
            myc_causal_node *a = &g->nodes[i];
            myc_causal_node *b = &g->nodes[j];
            int link = 0;

            if (symbols_overlap(a->symbols, b->symbols))
                link = 1;
            else if (a->line > 0 && a->line == b->line)
                link = 1;   /* lokasi sama (baris sama) */
            else if (res->witness && res->witness->violation_line > 0 &&
                     a->line == res->witness->violation_line &&
                     b->line == res->witness->violation_line)
                link = 1;   /* witness overlap */
            if (link)
                uf_union(parent, i, j);
        }
    }

    /* Normalisasi cluster_id + pilih root per cluster (confidence
     * tertinggi; tie-break line terkecil; note tidak pernah root). */
    for (i = 0; i < g->count; i++) {
        int r = uf_find(parent, i);
        g->nodes[i].cluster_id = r;
    }
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < g->count; i++) {
        int cid = g->nodes[i].cluster_id;
        if (!seen[cid]) {
            int best = i;
            seen[cid] = 1;
            for (j = i + 1; j < g->count; j++) {
                if (g->nodes[j].cluster_id != cid)
                    continue;
                if (node_rank(&g->nodes[j]) > node_rank(&g->nodes[best]) ||
                    (node_rank(&g->nodes[j]) == node_rank(&g->nodes[best]) &&
                     (g->nodes[j].line < g->nodes[best].line ||
                      (g->nodes[j].line == g->nodes[best].line &&
                       g->nodes[j].col < g->nodes[best].col)))) {
                    best = j;
                }
            }
            g->nodes[best].is_root = 1;
        }
    }

    /* Urutan perbaikan: semua ROOT dulu (urutan index diag), lalu
     * dependents per cluster. Tanpa sorting tambahan -- determinisme
     * dijamin oleh iterasi index yang stabil. */
    for (i = 0; i < g->count; i++) {
        if (g->nodes[i].is_root)
            g->repair_order[g->repair_count++] = g->nodes[i].diag_index;
    }
    for (i = 0; i < g->count; i++) {
        if (!g->nodes[i].is_root)
            g->repair_order[g->repair_count++] = g->nodes[i].diag_index;
    }
}

int myc_causal_first_confirmed_root(const myc_causal_graph *g)
{
    int i;
    if (!g)
        return -1;
    for (i = 0; i < g->count; i++) {
        if (g->nodes[i].is_root &&
            g->nodes[i].confidence >= MYC_CONF_CONFIRMED)
            return g->nodes[i].diag_index;
    }
    /* fallback: root apa pun */
    for (i = 0; i < g->count; i++) {
        if (g->nodes[i].is_root)
            return g->nodes[i].diag_index;
    }
    return -1;
}

char *myc_causal_json(const myc_causal_graph *g)
{
    json_value *root;
    json_value *arr;
    json_value *order;
    char *out;
    int i, ok;

    if (!g)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    arr = json_new_arr();
    if (!arr) { json_free(root); return NULL; }

    for (i = 0; i < g->count; i++) {
        const myc_causal_node *nd = &g->nodes[i];
        json_value *obj = json_new_obj();
        if (!obj) continue;
        json_obj_set(obj, "diag_index", json_new_num((int64_t)nd->diag_index));
        json_obj_set(obj, "line", json_new_num((int64_t)nd->line));
        json_obj_set(obj, "col", json_new_num((int64_t)nd->col));
        json_obj_set(obj, "cluster", json_new_num((int64_t)nd->cluster_id));
        json_obj_set(obj, "root", json_new_bool(nd->is_root ? 1 : 0));
        json_obj_set(obj, "note", json_new_bool(nd->is_note ? 1 : 0));
        json_obj_set(obj, "confidence",
                     json_new_num((int64_t)nd->confidence));
        if (nd->symbols)
            json_obj_set(obj, "symbols", json_new_str(nd->symbols));
        json_arr_push(arr, obj);
    }
    json_obj_set(root, "nodes", arr);

    order = json_new_arr();
    if (order) {
        for (i = 0; i < g->repair_count; i++)
            json_arr_push(order, json_new_num((int64_t)g->repair_order[i]));
        json_obj_set(root, "repair_order", order);
    }

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok) out = NULL;
    return out;
}

void myc_causal_free(myc_causal_graph *g)
{
    int i;
    if (!g)
        return;
    for (i = 0; i < g->count; i++)
        free(g->nodes[i].symbols);
    memset(g, 0, sizeof(*g));
}
