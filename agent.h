#ifndef MYC_AGENT_H
#define MYC_AGENT_H

#include "myc.h"
#include "prompt.h"

#define MYC_AGENT_SCHEMA "myc.agent.v2"
#define MYC_LITE_SCHEMA  "myc.lite.v1"
#define MYC_AGENT_MAX_FRONTIER 16
#define MYC_AGENT_MAX_PRESERVE 16
#define MYC_AGENT_MAX_FORBIDDEN 16
#define MYC_AGENT_PAYLOAD_CAP 16384

/* myc.lite.v1 action enum (beku, nilai baru hanya di akhir). Nama
 * panjang disengaja: STOP_COMPILE_CLEAN bukan "safe". */
typedef enum {
    MYC_LITE_STOP_COMPILE_CLEAN = 0,
    MYC_LITE_FIX_ONE,
    MYC_LITE_ESCALATE_RUNTIME,
    MYC_LITE_ESCALATE_CONTRACT,
    MYC_LITE_GIVE_UP_NO_TEMPLATE
} myc_lite_action;

typedef struct {
    char *finding_id;
    char *anchor;
    char *diagnostic_class;
    char *message;
    myc_confidence confidence;
    char *repro;
    char *witness_hash;
    /* Additive: f-<fn>-<span-sha8> di samping finding_id f-%08x. */
    char *source_anchor;
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

    /* NEMO-5: nama enrichment yang dibuang karena cap (urutan drop).
     * Kosong bila tidak ada drop; di-emit sebagai array string. */
#define MYC_AGENT_MAX_DROPPED 8
    char *payload_dropped[MYC_AGENT_MAX_DROPPED];
    int   payload_dropped_count;

    /* NEMO-6: snippet system-prompt deterministik (myc_prompt_build).
     * Enrichment; dibuang bersama pack saat cap. NULL bila source absen. */
    char *feedback;

    /* Project-local pack (Fase 7, DS-15 wiring): objek JSON berisi
     * prompt.md verbatim + spec (rules/allow/deny) + sha256 keduanya.
     * NULL bila pack absen/--no-pack ATAU dibuang oleh enforcement cap
     * (enrichment, dibuang TERAKHIR setelah next_best_json). */
    char *pack_json;

    /* Additive myc.lite.v1 action (satu aksi, sama dengan next_check). */
    myc_lite_action action;
    int has_action;
} myc_agent_result;

/* Paket ringkas untuk agen lemah (schema myc.lite.v1). Additive;
 * tidak mengganti myc.agent.v2. */
typedef struct {
    myc_verdict       verdict;
    myc_lite_action   action;
    myc_assurance_vector assurance;
    int               line;
    char             *claim;
    char             *finding_id;
    char             *function;
    char             *why;
    char             *fix_or_null;
    char             *allowed_span;
    char             *next_command;
    char             *receipt_sha256;
    char             *source_sha256;
    char             *source_anchor;
    char             *context_text; /* G3: myc context 4K bila GIVE_UP */
    int               cache_hit;
} myc_lite_result;

/* Inisialisasi dan pembebasan */
void myc_agent_result_init(myc_agent_result *ar);
void myc_agent_result_free(myc_agent_result *ar);

/* Bangun agent protocol dari myc_result. Mengembalikan 0 jika
   berhasil, -1 bila payload melebihi MYC_AGENT_PAYLOAD_CAP.
   pack: pack proyek lokal (myc_pack_load), NULL = tanpa pack.
   source/source_len: opsional (NULL/0 sah) untuk NEMO-2 runtime
   repair template; denylist tetap dari diag. */
int myc_build_agent_result(const myc_result *res,
                           myc_agent_result *ar,
                           const char *intent_hash,
                           const char *scenario_hash,
                           const myc_pack_info *pack,
                           const char *source,
                           size_t source_len);

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
 * path: NULL/"" -> token "<file>"; "-" tetap "-".
 * source opsional: dipakai membedakan FIX_ONE vs GIVE_UP (template).
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_agent_build_next_check(const myc_result *res,
                                 const char *path);
char *myc_agent_build_next_check_ex(const myc_result *res,
                                    const char *path,
                                    const char *source,
                                    size_t source_len);

/* Satu aksi lite dari verdict/gate/template (deterministik). */
myc_lite_action myc_agent_select_action(const myc_result *res,
                                        const char *source,
                                        size_t source_len);
const char *myc_lite_action_name(myc_lite_action a);

void myc_lite_result_init(myc_lite_result *lr);
void myc_lite_result_free(myc_lite_result *lr);
int myc_build_lite_result(const myc_result *res,
                          myc_lite_result *lr,
                          const char *source,
                          size_t source_len);
/* JSON malloc'd (caller myc_free). NULL bila OOM. */
char *myc_lite_result_json(const myc_lite_result *lr);

#endif