/*
 * abi_tx_reject.c -- unit test exit criteria SOL-14:
 * "ABI regression ditolak dalam transaction."
 *
 * Menyiapkan myc_transaction dengan snapshot ABI sebelum patch
 * (myc_transaction_set_abi_before) lalu memverifikasi patch dengan hasil
 * yang snapshot ABI-nya sama / berbeda:
 *   - drift (struct size berubah) -> MYC_TX_RESULT_REJECTED_ABI (hard);
 *   - sama -> MYC_TX_RESULT_ACCEPTED (finding CLEAN + verdict OK + complete).
 *
 * Exit 0 = PASS. Build: gcc -DMYC_NO_MAIN abi_tx_reject.c <PIPELINE>.
 */
#include <stdio.h>
#include <stdlib.h>

#include "myc.h"
#include "transaction.h"
#include "abi.h"

static int run_case(int expect_reject, int with_snapshot)
{
    myc_result     res;
    myc_transaction tx;
    myc_tx_result  r;

    myc_result_init(&res);
    res.finding = MYC_FINDING_CLEAN;
    res.verdict = MC_OK;
    res.completeness = MYC_COMPLETENESS_COMPLETE;
    res.abi_ran = with_snapshot ? 1 : 0;
    /* snapshot hasil patch (bukan arena; hanya dibaca verify) */
    res.abi_snapshot =
        "TARGET x86_64-pc-linux-gnu\n"
        "HEADER h\n"
        "SYMBOL int add(int,int)\n"
        "STRUCT Point size=8 align=4\n"
        "MEMBER Point x off=0\n"
        "MEMBER Point y off=4\n";

    myc_transaction_init(&tx, NULL, NULL, NULL, NULL, NULL);
    if (expect_reject)
        myc_transaction_set_abi_before(&tx,
            "TARGET x86_64-pc-linux-gnu\n"
            "HEADER h0\n"
            "SYMBOL int add(int,int)\n"
            "STRUCT Point size=12 align=4\n"   /* DRIFT: size berubah */
            "MEMBER Point x off=0\n"
            "MEMBER Point y off=4\n"
            "MEMBER Point z off=8\n");
    else
        myc_transaction_set_abi_before(&tx, res.abi_snapshot);

    r = myc_transaction_verify(&tx, NULL, NULL, 0, &res);

    myc_transaction_free(&tx);
    myc_result_free(&res);

    if (expect_reject == 1)        /* ABI drift -> hard reject */
        return r == MYC_TX_RESULT_REJECTED_ABI ? 0 : 1;
    if (expect_reject == 2)        /* gap: abi_before tanpa snapshot hasil */
        return r == MYC_TX_RESULT_REJECTED_PRESERVATION ? 0 : 1;
    return r == MYC_TX_RESULT_ACCEPTED ? 0 : 1;
}

int main(void)
{
    if (run_case(1, 1)) {
        fprintf(stderr, "FAIL: ABI drift TIDAK ditolak dalam transaction\n");
        return 1;
    }
    if (run_case(0, 1)) {
        fprintf(stderr, "FAIL: ABI sama malah ditolak dalam transaction\n");
        return 1;
    }
    if (run_case(2, 0)) {
        fprintf(stderr, "FAIL: gap ABI (hasil tanpa snapshot) tidak terlihat\n");
        return 1;
    }
    printf("abi_tx_reject: OK (drift ditolak, sama diterima, gap terlihat)\n");
    return 0;
}
