/*
 * state.c -- State-Machine Ghosting (Fase 5, SOL-13).
 *
 * Membangun "ghost state machine" dari deklarasi //@ sm:
 *     //@ sm state IDLE initial;
 *     //@ sm state BUSY;
 *     //@ sm event START;
 *     //@ sm trans IDLE --START--> BUSY;
 *
 * Scanner TEKS deterministik (bukan AST), NON-blocking observasi:
 * verdict TIDAK pernah turun karena analisis ini. Temuan:
 *   SINK / UNREACHABLE / NO_RECOVERY / UNDECLARED_STATE|EVENT /
 *   UNUSED_STATE|EVENT / NO_INITIAL / NO_FINAL / DUP_DECL.
 * Witness = urutan event terpendek (BFS) dari initial ke state bermasalah.
 */
#include "state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Buffer dinamis kecil                                             */
/* ---------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buf;

static int buf_put(buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        char  *nd = (char *)myc_realloc(b->data, ncap);
        if (!nd)
            return 0;
        b->data = nd;
        b->cap = ncap;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
    return 1;
}

static int buf_puts(buf *b, const char *s)
{
    size_t i;
    for (i = 0; s[i]; i++)
        if (!buf_put(b, s[i]))
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* Lexical helper                                                   */
/* ---------------------------------------------------------------- */

static int is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(int c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static size_t read_word(const char *s, size_t i, size_t len,
                        char *out, size_t outcap)
{
    size_t w = 0;
    while (i < len && w + 1 < outcap && is_ident_char((unsigned char)s[i]))
        out[w++] = s[i++];
    out[w] = '\0';
    return i;
}

/* ---------------------------------------------------------------- */
/* Raw declarations (pass 1)                                        */
/* ---------------------------------------------------------------- */

typedef struct {
    char name[64];
    int  line;
    int  is_initial;
    int  is_final;
} raw_state;

typedef struct {
    char name[64];
    int  line;
} raw_event;

typedef struct {
    char from[64];
    char event[64];
    char to[64];
    int  line;
} raw_trans;

typedef struct {
    int   kind;
    char  text[512];    /* >= linebuf[512] (anti -Wformat-truncation) */
    char  witness[640];
    int   line;
} raw_finding;

const char *myc_sm_finding_name(myc_sm_finding_kind k)
{
    switch (k) {
    case MYC_SM_SINK:            return "sink";
    case MYC_SM_UNREACHABLE:     return "unreachable";
    case MYC_SM_NO_RECOVERY:     return "no_recovery";
    case MYC_SM_UNDECLARED_STATE:return "undeclared_state";
    case MYC_SM_UNDECLARED_EVENT:return "undeclared_event";
    case MYC_SM_UNUSED_STATE:    return "unused_state";
    case MYC_SM_UNUSED_EVENT:    return "unused_event";
    case MYC_SM_NO_INITIAL:      return "no_initial";
    case MYC_SM_NO_FINAL:        return "no_final";
    case MYC_SM_DUP_DECL:        return "dup_decl";
    }
    return "unknown";
}

/* Tambah finding; return index finding baru (atau -1 bila cap penuh). */
static int add_finding(raw_finding *f, int *nf, int kind,
                       const char *text, int line)
{
    if (*nf >= MYC_SM_MAX_FINDINGS)
        return -1;   /* cap: senyap (observasi) */
    f[*nf].kind = kind;
    snprintf(f[*nf].text, sizeof(f[*nf].text), "%.511s", text);
    f[*nf].witness[0] = '\0';
    f[*nf].line = line;
    (*nf)++;
    return *nf - 1;
}

/* ---------------------------------------------------------------- */
/* Graf + BFS witness                                                */
/* ---------------------------------------------------------------- */

typedef struct {
    int from;   /* index state */
    int ev;     /* index event */
    int to;     /* index state */
} edge;

/* BFS terpendek dari start ke target atas edges (forward). parent[] =
 * pendahulu (parent[start]=start), pev[] = index event dari parent ke
 * state. Return 1 bila target terjangkau. */
static int sm_bfs(int nstates, const edge *edges, int nedges,
                  int start, int target, int *parent, int *pev)
{
    int q[MYC_SM_MAX_STATES];
    int head = 0, tail = 0;
    int i;
    for (i = 0; i < nstates; i++)
        parent[i] = -1;
    if (start < 0 || start >= nstates)
        return 0;
    parent[start] = start;
    pev[start] = -1;
    q[tail++] = start;
    while (head < tail) {
        int s = q[head++];
        if (s == target)
            return 1;
        for (i = 0; i < nedges; i++) {
            int t;
            if (edges[i].from != s)
                continue;
            t = edges[i].to;
            if (parent[t] == -1) {
                parent[t] = s;
                pev[t] = edges[i].ev;
                q[tail++] = t;
            }
        }
    }
    return 0;
}

/* Tulis urutan "A --e1--> B --e2--> C" dari BFS (parent/pev) ke out. */
static void sm_path_str(const char *const *snames, const char *const *enames,
                        const int *parent, const int *pev,
                        int start, int target, char *out, size_t cap)
{
    int stack[MYC_SM_MAX_STATES];
    int evs[MYC_SM_MAX_STATES];
    int n = 0, k, len = 0;
    int cur = target;
    size_t ucap = cap;
    while (cur != start && n < MYC_SM_MAX_STATES) {
        stack[n] = cur;
        evs[n] = pev[cur];
        n++;
        cur = parent[cur];
    }
    if (cur != start) {       /* tak terjangkau: kosongkan */
        out[0] = '\0';
        return;
    }
    len = snprintf(out, ucap, "%.63s", snames[start]);
    if (len < 0 || (size_t)len >= ucap) {
        out[ucap - 1] = '\0';
        return;
    }
    for (k = n - 1; k >= 0; k--) {
        int add = snprintf(out + len, ucap - (size_t)len, " --%.63s--> %.63s",
                           enames[evs[k]], snames[stack[k]]);
        if (add < 0 || (size_t)add >= ucap - (size_t)len) {
            out[ucap - 1] = '\0';
            return;
        }
        len += add;
    }
}

/* ---------------------------------------------------------------- */
/* Scan utama                                                        */
/* ---------------------------------------------------------------- */

int myc_sm_scan(const char *source, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;
    raw_state  st[MYC_SM_MAX_STATES];
    raw_event  ev[MYC_SM_MAX_EVENTS];
    raw_trans  tr[MYC_SM_MAX_TRANS];
    raw_finding fnd[MYC_SM_MAX_FINDINGS];
    int nst = 0, nev = 0, ntr = 0, nfnd = 0;
    int j, k;
    edge edges[MYC_SM_MAX_TRANS];
    int  nedges = 0;
    int  initial = -1;
    int  nfinal = 0;
    int  parent[MYC_SM_MAX_STATES];
    int  pev[MYC_SM_MAX_STATES];
    buf  rep;
    char linebuf[1024];   /* >= 2+16+2+500+8+10 (finding report) */

    res->sm_states = 0;
    res->sm_events = 0;
    res->sm_transitions = 0;
    res->sm_findings = 0;
    res->sm_report = NULL;

    /* ---- Pass 1: parse deklarasi //@ sm ---- */
    while (i < len) {
        char c = source[i];
        if (c == '\n') {
            line++;
            col = 1;
            i++;
            continue;
        }
        /* komentar blok: skip penuh */
        if (c == '/' && i + 1 < len && source[i + 1] == '*') {
            size_t end = i + 2;
            while (end + 1 < len &&
                   !(source[end] == '*' && source[end + 1] == '/'))
                end++;
            if (end + 1 < len)
                end += 2;
            while (i < end && i < len) {
                if (source[i] == '\n') {
                    line++;
                    col = 1;
                } else
                    col++;
                i++;
            }
            continue;
        }
        /* komentar // */
        if (c == '/' && i + 1 < len && source[i + 1] == '/') {
            size_t line_end = i;
            while (line_end < len && source[line_end] != '\n')
                line_end++;
            if (i + 2 < len && source[i + 2] == '@') {
                size_t p = i + 3;
                char   kw[32];
                size_t kwend;
                while (p < line_end &&
                       (source[p] == ' ' || source[p] == '\t'))
                    p++;
                kwend = read_word(source, p, line_end, kw, sizeof(kw));
                if (strcmp(kw, "sm") == 0) {
                    p = kwend;
                    while (p < line_end &&
                           (source[p] == ' ' || source[p] == '\t'))
                        p++;
                    kwend = read_word(source, p, line_end, kw, sizeof(kw));
                    if (strcmp(kw, "state") == 0) {
                        char name[64];
                        int  is_init = 0, is_fin = 0;
                        int  dup = 0;
                        p = kwend;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        kwend = read_word(source, p, line_end, name,
                                          sizeof(name));
                        if (name[0] != '\0') {
                            for (j = 0; j < nst; j++)
                                if (strcmp(st[j].name, name) == 0) {
                                    dup = 1;
                                    break;
                                }
                            if (dup) {
                                snprintf(linebuf, sizeof(linebuf),
                                         "deklarasi ganda state `%s`",
                                         name);
                                add_finding(fnd, &nfnd, MYC_SM_DUP_DECL,
                                            linebuf, (int)line);
                            } else if (nst < MYC_SM_MAX_STATES) {
                                p = kwend;
                                for (;;) {
                                    char mod[32];
                                    while (p < line_end &&
                                           (source[p] == ' ' ||
                                            source[p] == '\t'))
                                        p++;
                                    if (p >= line_end ||
                                        source[p] == ';')
                                        break;
                                    kwend = read_word(source, p, line_end,
                                                      mod, sizeof(mod));
                                    if (strcmp(mod, "initial") == 0)
                                        is_init = 1;
                                    else if (strcmp(mod, "final") == 0)
                                        is_fin = 1;
                                    else
                                        break;
                                    p = kwend;
                                }
                                snprintf(st[nst].name, 64, "%s", name);
                                st[nst].line = (int)line;
                                st[nst].is_initial = is_init;
                                st[nst].is_final = is_fin;
                                nst++;
                            }
                        }
                    } else if (strcmp(kw, "event") == 0) {
                        char name[64];
                        int  dup = 0;
                        p = kwend;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        read_word(source, p, line_end, name, sizeof(name));
                        if (name[0] != '\0') {
                            for (j = 0; j < nev; j++)
                                if (strcmp(ev[j].name, name) == 0) {
                                    dup = 1;
                                    break;
                                }
                            if (dup) {
                                snprintf(linebuf, sizeof(linebuf),
                                         "deklarasi ganda event `%s`",
                                         name);
                                add_finding(fnd, &nfnd, MYC_SM_DUP_DECL,
                                            linebuf, (int)line);
                            } else if (nev < MYC_SM_MAX_EVENTS) {
                                snprintf(ev[nev].name, 64, "%s", name);
                                ev[nev].line = (int)line;
                                nev++;
                            }
                        }
                    } else if (strcmp(kw, "trans") == 0) {
                        char from[64], evec[64], to[64];
                        int  dash2;
                        p = kwend;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        kwend = read_word(source, p, line_end, from,
                                          sizeof(from));
                        if (from[0] == '\0')
                            goto skip_line;
                        p = kwend;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        dash2 = 0;
                        if (p + 1 < line_end && source[p] == '-' &&
                            source[p + 1] == '-') {
                            p += 2;
                            dash2 = 1;
                        } else if (p < line_end && source[p] == '-') {
                            p += 1;
                        } else
                            goto skip_line;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        kwend = read_word(source, p, line_end, evec,
                                          sizeof(evec));
                        if (evec[0] == '\0')
                            goto skip_line;
                        p = kwend;
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        if (dash2) {
                            if (p + 2 < line_end && source[p] == '-' &&
                                source[p + 1] == '-' &&
                                source[p + 2] == '>')
                                p += 3;
                            else
                                goto skip_line;
                        } else {
                            if (p + 1 < line_end && source[p] == '-' &&
                                source[p + 1] == '>')
                                p += 2;
                            else
                                goto skip_line;
                        }
                        while (p < line_end &&
                               (source[p] == ' ' || source[p] == '\t'))
                            p++;
                        read_word(source, p, line_end, to, sizeof(to));
                        if (to[0] == '\0')
                            goto skip_line;
                        if (ntr < MYC_SM_MAX_TRANS) {
                            snprintf(tr[ntr].from, 64, "%s", from);
                            snprintf(tr[ntr].event, 64, "%s", evec);
                            snprintf(tr[ntr].to, 64, "%s", to);
                            tr[ntr].line = (int)line;
                            ntr++;
                        }
                    }
                }
            }
skip_line:
            col += (line_end - i);
            i = line_end;
            continue;
        }
        i++;
        col++;
    }

    if (nst == 0) {
        /* tidak ada machine: observasi kosong, tanpa report */
        return 1;
    }

    /* ---- Pass 2: validasi + graf + witness ---- */

    /* salin deklarasi ke hasil (arena) */
    for (j = 0; j < nst; j++) {
        myc_sm_state *s = &res->sm_state_list[j];
        memset(s, 0, sizeof(*s));
        s->name = myc_result_arena_dup(res, st[j].name, 0);
        s->line = st[j].line;
        s->is_initial = st[j].is_initial;
        s->is_final = st[j].is_final;
    }
    res->sm_states = nst;
    for (j = 0; j < nev; j++) {
        myc_sm_event *e = &res->sm_event_list[j];
        memset(e, 0, sizeof(*e));
        e->name = myc_result_arena_dup(res, ev[j].name, 0);
        e->line = ev[j].line;
    }
    res->sm_events = nev;

    /* transisi: validasi referensi (undeclared -> finding + skip) */
    for (j = 0; j < ntr; j++) {
        int fi = -1, ti = -1, ei = -1;
        for (k = 0; k < nst; k++)
            if (strcmp(st[k].name, tr[j].from) == 0) {
                fi = k;
                break;
            }
        for (k = 0; k < nst; k++)
            if (strcmp(st[k].name, tr[j].to) == 0) {
                ti = k;
                break;
            }
        for (k = 0; k < nev; k++)
            if (strcmp(ev[k].name, tr[j].event) == 0) {
                ei = k;
                break;
            }
        if (fi < 0 || ti < 0) {
            snprintf(linebuf, sizeof(linebuf),
                     "transisi `%.63s --%.63s--> %.63s` merujuk state tak "
                     "terdeklarasi (`%.63s`)",
                     tr[j].from, tr[j].event, tr[j].to,
                     fi < 0 ? tr[j].from : tr[j].to);
            add_finding(fnd, &nfnd, MYC_SM_UNDECLARED_STATE, linebuf,
                        tr[j].line);
            continue;
        }
        if (ei < 0) {
            snprintf(linebuf, sizeof(linebuf),
                     "transisi `%.63s --%.63s--> %.63s` merujuk event tak "
                     "terdeklarasi (`%.63s`)",
                     tr[j].from, tr[j].event, tr[j].to, tr[j].event);
            add_finding(fnd, &nfnd, MYC_SM_UNDECLARED_EVENT, linebuf,
                        tr[j].line);
            continue;
        }
        {
            myc_sm_trans *t = &res->sm_trans_list[res->sm_transitions];
            memset(t, 0, sizeof(*t));
            t->from = myc_result_arena_dup(res, tr[j].from, 0);
            t->event = myc_result_arena_dup(res, tr[j].event, 0);
            t->to = myc_result_arena_dup(res, tr[j].to, 0);
            t->line = tr[j].line;
            res->sm_transitions++;
        }
        edges[nedges].from = fi;
        edges[nedges].ev = ei;
        edges[nedges].to = ti;
        nedges++;
    }

    /* initial: flag eksplisit; bila tak ada, state pertama (finding) */
    for (j = 0; j < nst; j++)
        if (st[j].is_initial) {
            initial = j;
            break;
        }
    if (initial < 0) {
        initial = 0;
        snprintf(linebuf, sizeof(linebuf),
                 "tidak ada state initial; state pertama `%.63s` dipakai "
                 "initial implisit", st[0].name);
        add_finding(fnd, &nfnd, MYC_SM_NO_INITIAL, linebuf, st[0].line);
    }
    for (j = 0; j < nst; j++)
        if (st[j].is_final)
            nfinal++;
    if (nfinal == 0)
        add_finding(fnd, &nfnd, MYC_SM_NO_FINAL,
                    "tidak ada state final (mesin tanpa terminal)", 0);

    /* unused event / state */
    for (j = 0; j < nev; j++) {
        int used = 0;
        for (k = 0; k < nedges; k++)
            if (edges[k].ev == j) {
                used = 1;
                break;
            }
        if (!used) {
            snprintf(linebuf, sizeof(linebuf),
                     "event `%.63s` dideklarasikan tapi tidak dipakai "
                     "transisi mana pun", ev[j].name);
            add_finding(fnd, &nfnd, MYC_SM_UNUSED_EVENT, linebuf,
                        ev[j].line);
        }
    }
    for (j = 0; j < nst; j++) {
        int used = 0;
        for (k = 0; k < nedges; k++)
            if (edges[k].from == j || edges[k].to == j) {
                used = 1;
                break;
            }
        if (!used) {
            snprintf(linebuf, sizeof(linebuf),
                     "state `%.63s` dideklarasikan tapi tidak dipakai "
                     "transisi mana pun", st[j].name);
            add_finding(fnd, &nfnd, MYC_SM_UNUSED_STATE, linebuf,
                        st[j].line);
        }
    }

    /* array nama untuk witness */
    {
        const char *snames[MYC_SM_MAX_STATES];
        const char *enames[MYC_SM_MAX_EVENTS];
        for (j = 0; j < nst; j++)
            snames[j] = st[j].name;
        for (j = 0; j < nev; j++)
            enames[j] = ev[j].name;

        /* per-state: unreachable / sink / no-recovery (+ witness BFS) */
        for (j = 0; j < nst; j++) {
            int in = 0, out = 0;
            int ok, fidx;
            for (k = 0; k < nedges; k++) {
                if (edges[k].to == j)
                    in++;
                if (edges[k].from == j)
                    out++;
            }
            if (j != initial && in == 0) {
                snprintf(linebuf, sizeof(linebuf),
                         "state `%.63s` tidak pernah dicapai (tak ada "
                         "transisi masuk, bukan initial)", st[j].name);
                add_finding(fnd, &nfnd, MYC_SM_UNREACHABLE, linebuf,
                            st[j].line);
                continue;
            }
            if (out == 0 && !st[j].is_final) {
                snprintf(linebuf, sizeof(linebuf),
                         "state `%.63s` tidak punya transisi keluar dan "
                         "bukan final (dead state / sink)", st[j].name);
                fidx = add_finding(fnd, &nfnd, MYC_SM_SINK, linebuf,
                                   st[j].line);
                ok = sm_bfs(nst, edges, nedges, initial, j, parent, pev);
                if (fidx >= 0 && ok) {
                    sm_path_str(snames, enames, parent, pev, initial, j,
                                fnd[fidx].witness,
                                sizeof(fnd[fidx].witness));
                }
                continue;
            }
            if (j != initial && out > 0 && !st[j].is_final) {
                /* ada jalur kembali ke initial? BFS di graf terbalik */
                edge rev[MYC_SM_MAX_TRANS];
                int  nr = 0;
                for (k = 0; k < nedges; k++) {
                    rev[nr].from = edges[k].to;
                    rev[nr].ev = edges[k].ev;
                    rev[nr].to = edges[k].from;
                    nr++;
                }
                if (!sm_bfs(nst, rev, nr, initial, j, parent, pev)) {
                    snprintf(linebuf, sizeof(linebuf),
                             "state `%.63s` tak punya jalur kembali ke "
                             "initial `%.63s` (perangkap satu arah)",
                             st[j].name, st[initial].name);
                    fidx = add_finding(fnd, &nfnd, MYC_SM_NO_RECOVERY,
                                       linebuf, st[j].line);
                    ok = sm_bfs(nst, edges, nedges, initial, j, parent,
                                pev);
                    if (fidx >= 0 && ok) {
                        sm_path_str(snames, enames, parent, pev, initial,
                                    j, fnd[fidx].witness,
                                    sizeof(fnd[fidx].witness));
                    }
                }
            }
        }
    }

    /* ---- Report ---- */
    memset(&rep, 0, sizeof(rep));
    buf_puts(&rep,
             "state machine (SOL-13): ghost state machine dari //@ sm "
             "(observasi, NON-blocking)\n");
    buf_puts(&rep, "  states: ");
    for (j = 0; j < nst; j++) {
        if (j)
            buf_puts(&rep, ", ");
        buf_puts(&rep, st[j].name);
        if (st[j].is_initial)
            buf_puts(&rep, " (initial)");
        else if (st[j].is_final)
            buf_puts(&rep, " (final)");
    }
    buf_puts(&rep, "\n  events: ");
    for (j = 0; j < nev; j++) {
        if (j)
            buf_puts(&rep, ", ");
        buf_puts(&rep, ev[j].name);
    }
    buf_puts(&rep, "\n  transitions:\n");
    for (j = 0; j < res->sm_transitions; j++) {
        const myc_sm_trans *t = &res->sm_trans_list[j];
        snprintf(linebuf, sizeof(linebuf), "    %.63s --%.63s--> %.63s\n",
                 t->from, t->event, t->to);
        buf_puts(&rep, linebuf);
    }
    if (nfnd > 0) {
        buf_puts(&rep, "  findings:\n");
        for (j = 0; j < nfnd; j++) {
            snprintf(linebuf, sizeof(linebuf),
                     "    [%.16s] %.500s (line %d)\n",
                     myc_sm_finding_name(
                         (myc_sm_finding_kind)fnd[j].kind),
                     fnd[j].text, fnd[j].line);
            buf_puts(&rep, linebuf);
            if (fnd[j].witness[0]) {
                snprintf(linebuf, sizeof(linebuf),
                         "      witness: %.600s\n", fnd[j].witness);
                buf_puts(&rep, linebuf);
            }
        }
    }
    snprintf(linebuf, sizeof(linebuf),
             "  ringkasan: %d state, %d event, %d transisi, %d finding\n",
             nst, nev, res->sm_transitions, nfnd);
    buf_puts(&rep, linebuf);
    buf_puts(&rep, "  (state machine = observasi; tulis //@ sm state/"
                   "event/trans untuk mendeklarasikan)\n");
    if (rep.data) {
        res->sm_report = myc_result_arena_dup(res, rep.data, 0);
        myc_free(rep.data);
    }

    /* salin findings ke hasil (arena) */
    for (j = 0; j < nfnd; j++) {
        myc_sm_finding *f = &res->sm_finding_list[j];
        memset(f, 0, sizeof(*f));
        f->kind = (myc_sm_finding_kind)fnd[j].kind;
        f->text = myc_result_arena_dup(res, fnd[j].text, 0);
        f->witness = myc_result_arena_dup(res, fnd[j].witness, 0);
        f->line = fnd[j].line;
    }
    res->sm_findings = nfnd;

    return 1;
}
