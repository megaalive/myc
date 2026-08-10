#ifndef MYC_AGENT_H
#define MYC_AGENT_H

#include "myc.h"
#include "prompt.h"

#define MYC_AGENT_SCHEMA "myc.agent.v2"
#define MYC_AGENT_MAX_FRONTIER 16
#define MYC_AGENT_MAX_PRESERVE 16
#define MYC_AGENT_MAX_FORBIDDEN 16
#define MYC_AGENT_PAYLOAD_CAP 16384

typedef struct {
    char *finding_id;
    char *anchor;
    char *diagnostic_class;
    char *message;
    myc_confidence confidence;
    char *repro;
    char *witness_hash;
} myc_agent_finding;

typedef struct {
    char *region;
    char *description;
} myc_agent_edit;

typedef struct {
    char *symbol;
    char *reason;
} myc_agent_preserve;

typedef struct {
    char *region;
    char *reason;
} myc_agent_forbidden;

typedef struct {
    char *finding_id;
    char *command;
} myc_agent_next_check;

typedef struct {
    char *schema;
    char *intent_hash;
    char *scenario_hash;
    char *source_sha256;
    char *receipt_sha256;

    myc_finding finding;
    myc_verdict verdict;
    myc_assurance_vector assurance;

    /* Primary action (one only) */
    myc_agent_finding primary_finding;
    int has_primary;

    /* Witness */
    char *witness_text;
    char *witness_repro;
    char *witness_slice;

    /* Allowed edits */
    myc_agent_edit allowed_edits[MYC_AGENT_MAX_FRONTIER];
    int allowed_edit_count;

    /* Preserve obligations */
    myc_agent_preserve preserve[MYC_AGENT_MAX_PRESERVE];
    int preserve_count;

    /* Forbidden changes */
    myc_agent_forbidden forbidden[MYC_AGENT_MAX_FORBIDDEN];
    int forbidden_count;

    /* Next verification command */
    myc_agent_next_check next_check;
    int has_next_check;

    /* Unverified frontier */
    char *frontier[MYC_AGENT_MAX_FRONTIER];
    int frontier_count;

    /* Experiments (Fase 3, SOL-17): set eksperimen dari observasi,
     * diserialisasi JSON (myc_experiment_json). NULL bila tidak ada. */
    char *experiments_json;

    /* Causal Finding Graph (Fase 3, SOL-09): cluster finding terkait,
     * root cause dulu + dependent findings ditahan. Diserialisasi JSON
     * (myc_causal_json). NULL bila tidak ada finding terkait. */
    char *causal_json;

    /* Next-Best Experiment (Fase 3, SOL-03): rekomendasi eksperimen
     * termurah/menjanjikan dari frontier status, ranked by score.
     * Diserialisasi JSON (myc_nextbest_json). NULL bila tidak ada. */
    char *next_best_json;

    /* Delta vs previous receipt (NULL bila run pertama) */
    char *delta_receipt_sha;

    /* Payload size (for budget enforcement) */
    size_t payload_size;

    /* Cap payload yang DIPAKAI run ini (Fase 7 privacy/size controls):
     * 0 = default MYC_AGENT_PAYLOAD_CAP; nilai dari res->agent_payload_cap
     * (--agent-payload-cap). Diserialisasi di JSON agent sbg payload_cap. */
    size_t payload_cap;

    /* Project-local pack (Fase 7, DS-15 wiring): objek JSON berisi
     * prompt.md verbatim + spec (rules/allow/deny) + sha256 keduanya.
     * NULL bila pack absen/--no-pack ATAU dibuang oleh enforcement cap
     * (enrichment, dibuang TERAKHIR setelah next_best_json). */
    char *pack_json;
} myc_agent_result;

/* Inisialisasi dan pembebasan */
void myc_agent_result_init(myc_agent_result *ar);
void myc_agent_result_free(myc_agent_result *ar);

/* Bangun agent protocol dari myc_result. Mengembalikan 0 jika
   berhasil, -1 bila payload melebihi MYC_AGENT_PAYLOAD_CAP.
   pack: pack proyek lokal (myc_pack_load), NULL = tanpa pack. */
int myc_build_agent_result(const myc_result *res,
                           myc_agent_result *ar,
                           const char *intent_hash,
                           const char *scenario_hash,
                           const myc_pack_info *pack);

/* Serialisasi JSON ke buffer statis (terbatas). Mengembalikan
   pointer ke buffer internal (tidak perlu dibebaskan). */
const char *myc_agent_result_json(const myc_agent_result *ar);

/* Pilih primary finding dari myc_result. Mengembalikan NULL
   bila tidak ada finding yang bisa dipilih sebagai aksi utama. */
const myc_agent_finding *myc_agent_select_primary(const myc_result *res);

/* Bangun witness dari myc_result (repro + causal slice).
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_agent_build_witness(const myc_result *res);

/* Bangun next_check command string.
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_agent_build_next_check(const myc_result *res);

#endif