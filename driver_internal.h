/*
 * driver_internal.h -- Tipe + helper bersama gate driver / exhaustive / fuzz.
 *
 * Bukan API publik. Hanya driver.c, exhaustive.c, fuzz.c.
 */
#ifndef MYC_DRIVER_INTERNAL_H
#define MYC_DRIVER_INTERNAL_H

#include "myc.h"

#include <stddef.h>
#include <stdarg.h>

#ifdef _WIN32
#define myc_mkdir(path) _mkdir(path)
#define myc_rmdir(path) _rmdir(path)
#define myc_getpid() _getpid()
#define my_getcwd(buf,sz) _getcwd(buf,sz)
#else
#define myc_mkdir(path) mkdir(path, 0700)
#define myc_rmdir(path) rmdir(path)
#define myc_getpid() getpid()
#define my_getcwd(buf,sz) getcwd(buf,sz)
#endif

#define DRV_MAX_FUNCS  8
#define DRV_MAX_PARAMS 6
#define DRV_MAX_REQS   4
#define DRV_MAX_CASES  MYC_MAX_DRIVER_CASES
#define DRV_MAX_CANDS  8
#define DRV_MAX_LEN    128
#define DRV_BUF_CAP    65536

#define ASAN_DLL_NAME "clang_rt.asan_dynamic-x86_64.dll"

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} drv_buf;

typedef struct {
    char  name[DRV_MAX_LEN];
    char  type[DRV_MAX_PARAMS][DRV_MAX_LEN];
    char  pname[DRV_MAX_PARAMS][DRV_MAX_LEN];
    int   is_ptr[DRV_MAX_PARAMS];
    int   elem[DRV_MAX_PARAMS];
    int   nparams;
    char  reqs[DRV_MAX_REQS][512];
    int   nreqs;
    int   unsupported;
    char  ret[DRV_MAX_LEN];
    int   ret_void;
    int   ret_ptr;
} drv_func;

typedef struct {
    long lo, hi;
    int  has_lo, has_hi;
} drv_bounds;

int  drv_buf_put(drv_buf *b, char c);
int  drv_buf_putn(drv_buf *b, const char *s, size_t n);
int  drv_buf_puts(drv_buf *b, const char *s);
int  drv_buf_printf(drv_buf *b, const char *fmt, ...);

void parse_bound(const char *expr, const char *name, drv_bounds *bd);
int  scan_contract_funcs(const char *src, size_t len, drv_func *funcs,
                         int maxfuncs);
void add_diag_drv(myc_result *res, const char *msg);
char *drv_join_path(const char *dir, const char *name);
char *drv_make_temp_dir(void);
int  drv_marker_found(const char *out, const char *err);

#ifdef _WIN32
int  drv_copy_file(const char *src, const char *dst);
char *drv_asan_dll_path(const char *clang_path);
#endif

#endif /* MYC_DRIVER_INTERNAL_H */
