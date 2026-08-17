/*
 * experiment_cost.h -- satu tabel biaya/severity eksperimen (G4).
 *
 * eig.c, nextbest.c, dan observation.c memakai angka yang sama agar
 * rekomendasi tidak drift. Perilaku identik dengan tabel DS-14 yang
 * sudah di-golden di EIG; jangan ubah angka tanpa tes EIG.
 */
#ifndef MYC_EXPERIMENT_COST_H
#define MYC_EXPERIMENT_COST_H

#include "observation.h"

static inline int myc_experiment_cost_ms(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 5000;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 2500;
    case MYC_EXPERIMENT_SHORT_IO:         return 2000;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 2000;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 1500;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 1500;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 4000;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 4000;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 3000;
    default:                              return 3000;
    }
}

static inline int myc_experiment_severity(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 3;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 3;
    case MYC_EXPERIMENT_SHORT_IO:         return 2;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 2;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 2;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 3;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 2;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 2;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 1;
    default:                              return 1;
    }
}

#endif /* MYC_EXPERIMENT_COST_H */
