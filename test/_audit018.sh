#!/usr/bin/env bash
# =====================================================================
# _audit018.sh -- MYC-AUDIT-018: test portabel (Windows git-bash + POSIX).
#
# Menutup celah audit: test lama dominan .bat (Windows) dan tidak menguji
# concurrency/deadlock/OOM. Runner ini membangun + menjalankan unit test C
# portabel:
#   1. proc_flood    -- deadlock stdin/stdout, flood 100MiB prefix+tail,
#                      env override (MYC-AUDIT-002/017 + bounded capture).
#   2. oom_guards    -- guard overflow arena + input ekstrem.
#   3. oom_alloc     -- injeksi kegagalan malloc/calloc/realloc via allocator
#                      wrapper FORMAL (PR-019/P7-T02: alloc.c + MYC_ALLOC_TEST
#                      -> myc_alloc_set_fail_after Nth; TIDAK lagi --wrap),
#                      incl. fase JSON (MYC-AUDIT-009 sb_reserve/obj_set).
#   4. stress_threads-- concurrency myc_run paralel (Fase 5, juga Windows).
#   5. audit_lampiran-- lampiran A: exec-vs-127, temp path, contract panjang,
#                      NUL portability, 0 driver cases, immutable, fp-long
#                      (T8), file_path-only (T9), canary failure (T11),
#                      + varian ASan untuk fp-long (AUDIT-005 OOB).
#   6. filc gate     -- uji gate --filc bila filc-clang tersedia di PATH
#                      (ok_filc → L5 FILC, bad_filc_oob → FILC_VIOLATION).
#   7. reducer_exhaustive -- PR-003: kombinasi status gate pada
#                      myc_reduce_verdict (INV-001/002/003/011, exhaustif).
#   8. proc_fixture    -- PR-005 (P1-T02): hostile child fixture standalone
#                      (exit/sleep/stdout/stderr/both/read-stdin/close-*/
#                      spawn-child/spawn-grandchild/crash/hang/ordering/
#                      unicode/binary) + smoke test tiap mode.
#   9. proc_deadlock_matrix -- PR-006 (P1-T03): deadlock matrix via
#                      myc_proc_run terhadap proc_fixture: Cartesian I/O
#                      (0/4K/256K/8M stdin/stdout/stderr) x order x timeout
#                      x output cap + stress loop (zero deadlock/orphan/
#                      stuck worker, bounded memory).
#  10. proc_tree_kill -- PR-007 (P1-T04): process-tree cleanup pada timeout
#                      via myc_proc_run: chain 3-level, breakaway attempt
#                      (Job Object), nested job (fixture job), inherited
#                      handles (detach), chain normal exit.
#  11. evidence_spoof  -- PR-008 (P2-T02/INV-006): korpus spoof bukti
#                      semantik — teks mirip ASan/UBSan/GCC/Frama-C/Fil-C/
#                      marker internal via stdout/stderr/file report/
#                      komentar/nama file TIDAK boleh jadi evidence (zero
#                      false violation); regression hardening report
#                      sanitizer wajib exit != 0.
#  12. backend_abuse   -- PR-009 (P2-T03 tahap 1): parser-abuse corpus
#                      deterministik via fake backend (tests/backend_fake.c)
#                      — GCC JSON/text diagnostics, Fil-C, Frama-C Eva,
#                      internal JSON + konsumen (budget/scenario/calib/
#                      cache), sanitizer report files. Invariant: NEVER
#                      crash; NEVER promote malformed evidence to clean
#                      (INV-001) atau ke finding palsu (INV-011).# 13. parser_fuzz     -- PR-010 (P2-T03 tahap 2): fuzz harness parser
#                      deterministik (xorshift32, seed tetap). Seed awal =
#                      korpus PR-009; mutasi P2-T03 (bit flip, byte
#                      ins/del/set, truncation tiap byte, dup key, deep
#                      nesting, huge numbers, NUL, UTF-8 invalid, oversized,
#                      reorder, splice, unknown enum) terhadap json_parse +
#                      konsumen (budget/calib/scenario/cache) LANGSUNG dan
#                      parser GCC/Fil-C/Eva E2E via fake backend mode
#                      payload-file (byte mutasi apa pun). Invariant: NEVER
#                      crash; garbage tanpa marker kanonik TIDAK pernah jadi
#                      finding (INV-006); exit 0 + teks bukan bukti;
#                      round-trip JSON stabil. Seed crash/semantic
#                      di-persist ke .myc/regression/parser_*.bin +
#                      parser-index.txt; `--replay` menjalankan ulang semua
#                      seed (backstop). ASan lane (13b) bila toolchain ada.
#  14. cache_key_matrix -- PR-011 (MYC-AUDIT-043): cache key specification
#                      dimension-by-dimension hit/miss. Key kanonik v2
#                      (docs/cache-key.md) HARUS berubah bila salah satu
#                      dimensi yang mengubah hasil verifikasi berubah:
#                      source, flag gate inti (scenario hash), flag gate
#                      Fase 5/6 (g2), budget contract, eksekusi (stdin/
#                      timeout/output cap/header dir), cwd, tool identity;
#                      dan TETAP sama bila semua dimensi sama (determinisme
#                      + replay identik SOL-18). Gap v1 ditemukan &
#                      diperbaiki: --run-stdin / timeout_ms /
#                      max_output_bytes / checked_header_dir / flag Fase
#                      5/6 sebelumnya TIDAK di key (replay stale/lossy).
#                      Juga: dedup key sama, run stateful (assumption ack /
#                      require-closed) tidak di-store, hasil error tidak
#                      di-store, no_cache nonaktif.
#  15. atomic_state  -- PR-012 (MYC-AUDIT-044, P3-T03): atomic .myc state
#                      writes via persist.c (myc_persist_atomic_write):
#                      tulis temp + flush + fsync/FlushFileBuffers +
#                      rename/replace atomik; crash kapan pun -> state
#                      OLD valid ATAU NEW valid, tidak pernah setengah
#                      (crash-simulasi: temp stale dibersihkan, target
#                      valid JSON selalu). E2E semua penulis .myc:
#                      cache/ledger/assumptions/calibration/profile/
#                      regression seed; scan akhir NOL leftover *.tmp.*.
#  16. cache_corrupt -- PR-013 (MYC-AUDIT-045, P3-T04): cache corruption
#                      recovery. Injeksi korupsi deterministik ke
#                      .myc/evidence_cache.json (truncated JSON, flipped
#                      bits, unknown schema, mismatched hash, duplicate
#                      entry, stale backend version, malformed timestamp,
#                      impossible gate state, schema lama tanpa hash,
#                      non-object entry, garbage) -> replay MUST MISS
#                      (reject/quarantine + stderr diagnostic + self-heal)
#                      -> bukti dihitung ulang (recompute); NEVER crash
#                      dan NEVER replay hasil korup (verdict out-of-range
#                      tidak pernah di-clamp ke OK).
#  17. receipt_vectors -- PR-014 (MYC-AUDIT-046): canonical test vectors
#                      untuk receipt_sha256. Byte-string yang di-hash
#                      (docs/receipt-canonical.md) dibekukan: golden
#                      vector V1-V4 (string kanonik + sha256 hex dihitung
#                      INDEPENDEN via python3 hashlib), implementasi
#                      referensi independen di dalam test, konsistensi
#                      pipeline (receipt_sha256 hasil reduce == golden),
#                      determinisme, sensitivitas komponen (fingerprint /
#                      source_sha / gate status / gate id / urutan insert /
#                      jumlah gate / verdict manual), myc_rebuild_receipt,
#                      dan truncation buffer (cap-1 + NUL). Mengubah
#                      format kanonik / enum mapping / urutan append =
#                      test langsung gagal.
# 18. schema_compat -- PR-015 (MYC-AUDIT-047): freeze machine API
#                      schemas + golden files (docs/schema-registry.md,
#                      test/golden/). SEMUA skema JSON mesin dibekukan:
#                      myc.result.v1 (--json-summary), myc.agent.v2
#                      (--agent), myc.calibration.v1 (.myc/calibration.json),
#                      evidence cache (.myc/evidence_cache.json), scenario
#                      profile (myc.scenario.v1), pack spec (myc.spec.v1),
#                      MCP JSON-RPC 2.0 envelope. Test membuktikan: golden
#                      ter-parse (tidak busuk); field/tipe/enum sesuai
#                      tabel beku; konsumen (calib/scenario/pack/cache)
#                      MENERIMA golden; fail-closed pada versi tak dikenal
#                      (scenario v2 di-ignore, spec v99 fail-fast, cache
#                      verdict out-of-range dikarantina, calib korup di-
#                      ignore — INV-011); evolution additive (field asing
#                      tetap diterima konsumen lama); produsen
#                      (myc_result_to_json, myc_agent_result_json) masih
#                      memancarkan SEMUA field beku. Perubahan skema tanpa
#                      update golden = FAIL langsung.
# 19. mcp_abuse     -- PR-016 (P4-T04): MCP abuse & soak. mcp.exe
#                      (JSON-RPC 2.0 stdio) di-abuse: korpus protokol
#                      malformed deterministik (json invalid/truncated,
#                      root non-objek, jsonrpc/method/id tipe salah,
#                      unknown method, tools/call params/name/arguments
#                      salah, flags non-array/entry non-string (hardening
#                      PR-016), unknown flag, id null/string, dup key,
#                      notifikasi) + huge payload (baris ~9 MiB > cap
#                      8 MiB, drain tanpa crash) + duplicate id + soak
#                      1.090 request (1.000 ping + light tools +
#                      malformed). Invariant P4-T04: stdout TETAP
#                      protocol-clean (tiap baris = respons JSON-RPC 2.0
#                      sah; id di-echo; tepat satu result/error); mcp
#                      tidak pernah crash/hang; stderr kosong. Juga
#                      mengunci bug proc.c drain_assemble: output kosong
#                      -> shown=0 (bukan 1 byte heap stale).
# 20. backends       -- PR-017 (P5-T01/P5-T02): backend qualification
#                      registry. `myc backends` mencantumkan SEMUA backend
#                      (compile/analyzer/run/driver/exhaustive/fuzz/mutate/
#                      stack/lint/checked/prove/filc/matrix) dengan tier
#                      kebijakan A/B/C + path + versi EXACT (identitas
#                      backend = evidence, INV-013) + jumlah canary per
#                      backend; backend WSL-only (prove/filc) jujur
#                      menampilkan "via WSL" bila wsl.exe tersedia.
#                      Kualifikasi canary (P5-T02: backend terbukti hidup)
#                      dijalankan per backend cepat (compile) + seluruh
#                      swarm via `myc canary run` (11/11 di CI
#                      _ci_linux.sh / _regress_run.bat Fase 6).
# 21. limits          -- PR-018 (P7-T01): resource ceilings. `myc limits`
#                      mencantumkan SEMUA batas resource (tabel kebenaran)
#                      + kelas enforcement (HARD = ingress fail-fast,
#                      soft = cap + debt MYC-INCOMPLETE-RESOURCE-LIMIT);
#                      `--json` = objek myc.limits.v1 (29 entri beku).
#                      Debt tipe resource_limit TERTYPE diuji JALUR NYATA:
#                      `ok_driver_bounded.c --driver` (budget kombinatorial
#                      memotong kasus) -> MYC-INCOMPLETE-RESOURCE-LIMIT
#                      muncul sambil verdict TETAP OK (NON-blocking);
#                      `--require-complete` menaikkan ke INCONCLUSIVE (9.10).
#                      NON-blocking: limits hanyalah laporan.
# 22. allocator        -- PR-019 (P7-T02): allocator wrapper FORMAL
#                      myc_malloc/myc_calloc/myc_realloc/myc_free (alloc.c/h).
#                      Produksi = passthrough libc (nol overhead); test build
#                      (MYC_ALLOC_TEST) menggagalkan alokasi ke-N via
#                      myc_alloc_set_fail_after -- TIDAK lagi butuh GNU ld
#                      --wrap. Diverifikasi: (a) TIDAK ada panggilan mentah
#                      malloc/calloc/realloc/free tersisa di source myc
#                      (semua lewat wrapper; oom_alloc dibangun dengan
#                      MYC_ALLOC_TEST dan menutup 0..N titik alokasi tanpa
#                      crash + persistent state tidak korup), (b) alloc.c
#                      menyediakan hook nth-failure.
#
# Dijalankan dari _regress_run.bat (bila bash tersedia) atau langsung di
# POSIX/CI Linux. CWD harus root proyek.
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

SRCS="myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c sanloc.c contract.c state.c abi.c resource.c units.c profile.c calibrate.c eig.c candidate.c prove.c filc.c driver.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c persist.c limit.c alloc.c"
CC="${CC:-gcc}"
# POSIX/Windows butuh -pthread untuk stress_threads (pthread_create/join).
# Deteksi apakah kompiler menerima flag; aman untuk MinGW juga.
PTHREAD=""
if "$CC" -pthread -o /dev/null -x c - 2>/dev/null <<'EOF'
int main(void){return 0;}
EOF
then
    PTHREAD="-pthread"
fi
FAIL=0

rm -f test/proc_flood test/proc_flood.exe test/oom_guards test/oom_guards.exe \
      test/oom_alloc test/oom_alloc.exe test/stress_threads test/stress_threads.exe \
      test/reducer_exhaustive test/reducer_exhaustive.exe \
      test/proc_fixture test/proc_fixture.exe \
      test/proc_deadlock_matrix test/proc_deadlock_matrix.exe \
      test/proc_tree_kill test/proc_tree_kill.exe \
      test/evidence_spoof test/evidence_spoof.exe \
      test/evidence_spoof_fixture test/evidence_spoof_fixture.exe \
      test/backend_fake test/backend_fake.exe \
      test/backend_abuse test/backend_abuse.exe \
      test/backend_abuse.log \
      test/parser_fuzz test/parser_fuzz.exe \
      test/parser_fuzz_asan test/parser_fuzz_asan.exe \
      test/parser_fuzz.log test/parser_fuzz_asan.log \
      test/cache_key_matrix test/cache_key_matrix.exe \
      test/cache_key_matrix.log \
      test/atomic_state test/atomic_state.exe \
      test/atomic_state.log \
      test/cache_corrupt test/cache_corrupt.exe \
      test/cache_corrupt.log \
      test/receipt_vectors test/receipt_vectors.exe \
      test/receipt_vectors.log \
      test/sanloc_test test/sanloc_test.exe \
      test/sanloc_test.log \
      test/regress_replay_test test/regress_replay_test.exe \
      test/regress_replay_test.log \
      test/runtime_repair_test test/runtime_repair_test.exe \
      test/runtime_repair_test.log \
      test/agent_nemo_test test/agent_nemo_test.exe \
      test/agent_nemo_test.log \
      test/schema_compat test/schema_compat.exe \
      test/schema_compat.log \
      test/mcp_abuse test/mcp_abuse.exe \
      test/mcp_abuse.log \
      test/.parser_fuzz_payload.bin test/.parser_fuzz_scen.json
rm -rf test/.backend_fake_filc test/.parser_fuzz_filc test/.parser_fuzz_frama
rm -rf test/.cache_key_tmp test/.atomic_tmp test/.cache_corrupt_tmp
rm -rf test/.schema_compat_tmp test/.mcp_abuse_tmp test/.replay_tmp

run_built() {
    local name="$1"; shift
    if "$@"; then
        echo "[OK] $name"
    else
        echo "[FAIL] $name"
        FAIL=1
    fi
}

# --- 1. proc_flood: deadlock + flood + env override ---
if $CC -O2 -std=c11 -Wall -Wextra -I. $PTHREAD -o test/proc_flood test/proc_flood.c proc.c alloc.c 2>/dev/null; then
    run_built "audit018 proc_flood (deadlock/flood/env)" test/proc_flood
else
    echo "[FAIL] audit018 proc_flood gagal dibangun"
    FAIL=1
fi

# --- 2. oom_guards: guard overflow arena + input ekstrem ---
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/oom_guards \
       test/oom_guards.c $SRCS 2>/dev/null; then
    run_built "audit018 oom_guards (arena overflow/input)" test/oom_guards
else
    echo "[FAIL] audit018 oom_guards gagal dibangun"
    FAIL=1
fi

# --- 3. oom_alloc: injeksi kegagalan alokasi via allocator wrapper FORMAL ---
# PR-019 (P7-T02): alloc.c dibangun dengan -DMYC_ALLOC_TEST sehingga hook
# nth-allocation failure aktif (myc_alloc_set_fail_after). Tidak lagi butuh
# GNU ld --wrap. alloc.c sudah termuat di $SRCS; flag -DMYC_ALLOC_TEST
# hanya dibaca alloc.c, aman untuk seluruh translation unit.
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -DMYC_ALLOC_TEST \
       -o test/oom_alloc test/oom_alloc.c $SRCS 2>/dev/null; then
    run_built "audit018 oom_alloc (OOM injection via myc_alloc hook)" test/oom_alloc
else
    echo "[FAIL] audit018 oom_alloc gagal dibangun (MYC_ALLOC_TEST)"
    FAIL=1
fi

# --- 4. stress_threads: concurrency (juga dijalankan _regress_run.bat) ---
if $CC -O2 -std=c11 -Wall -Wextra -I. $PTHREAD -DMYC_NO_MAIN -o test/stress_threads \
       test/stress_threads.c $SRCS 2>/dev/null; then
    run_built "audit018 stress_threads (concurrency)" test/stress_threads
else
    echo "[FAIL] audit018 stress_threads gagal dibangun"
    FAIL=1
fi

# --- 5. verify_descendants: MYC-AUDIT-011 (POSIX-only: butuh fork) ---
# Grandchild yang di-fork child harus ikut mati saat myc membunuh process
# group pada timeout. MinGW/MSYS/CYGWIN tidak menyediakan fork() -> skip.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        echo "[SKIP] audit018 verify_descendants (POSIX-only, fork tak tersedia)"
        ;;
    *)
        if $CC -O2 -std=c11 -Wall -Wextra -I. -o test/verify_descendants \
               test/verify_descendants.c proc.c alloc.c 2>/dev/null; then
            run_built "audit018 verify_descendants (group kill mematikan descendant)" \
                      test/verify_descendants
        else
            echo "[FAIL] audit018 verify_descendants gagal dibangun"
            FAIL=1
        fi
        ;;
esac

# --- 6. audit_lampiran: lampiran A roadmap (regression test portabel) ---
rm -f test/audit_lampiran test/audit_lampiran.exe
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/audit_lampiran \
       test/audit_lampiran.c $SRCS 2>/dev/null; then
    run_built "audit_lampiran (gap lampiran A: exec/contract/run)" test/audit_lampiran
else
    echo "[FAIL] audit_lampiran gagal dibangun"
    FAIL=1
fi

# --- 6b. Varian ASan untuk T8 (fp-long): menangkap OOB read regresi
# MYC-AUDIT-005 secara EKSPLISIT. Butuh toolchain dengan -fsanitize=address
# (mis. clang/gcc WSL); MinGW Windows biasanya tak punya ASan runtime ->
# skip (bukan klaim). Bila ASan tersedia dan fingerprint memicu OOB read,
# proses akan di-abort ASan (exit 1) -> run_built menandai FAIL. ---
if $CC -fsanitize=address -o /dev/null -x c - 2>/dev/null <<'EOF'
int main(void){return 0;}
EOF
then
    if $CC -O1 -g -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
           -fsanitize=address -fno-omit-frame-pointer \
           -o test/audit_lampiran_asan test/audit_lampiran.c $SRCS 2>/dev/null; then
        run_built "audit_lampiran fp-long ASan (AUDIT-005 OOB)" \
                  test/audit_lampiran_asan --fp-long
    else
        echo "[FAIL] audit_lampiran fp-long ASan gagal dibangun"
        FAIL=1
    fi
else
    echo "[SKIP] audit_lampiran fp-long ASan (toolchain ASan tak tersedia)"
fi

# --- 7. reducer_exhaustive: PR-003 verdict reducer (INV-001/002/003/011) ---
# Kombinasi typed gate status pada myc_reduce_verdict() diekshaustifkan
# (49 + 343 kombinasi + kasus invariant); kegagalan = reducer menyimpang
# dari semantik terdokumentasi (no evidence -> tidak pernah clean, bug
# mendominasi incompleteness, observasi benign, unknown fails closed).
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/reducer_exhaustive \
       test/reducer_exhaustive.c $SRCS 2>/dev/null; then
    run_built "audit018 reducer_exhaustive (PR-003 verdict reducer)" \
              test/reducer_exhaustive
else
    echo "[FAIL] audit018 reducer_exhaustive gagal dibangun"
    FAIL=1
fi

# --- 8. proc_fixture: PR-005 hostile child fixture (smoke semua mode) ---
# Binary standalone (tanpa myc) dengan mode child bermusuhan deterministik;
# konsumen nyata = deadlock matrix (PR-006) + process-tree kill (PR-007).
# Smoke di sini membuktikan tiap mode berperilaku seperti didokumentasikan.
TMO=()
if command -v timeout >/dev/null 2>&1; then
    TMO=(timeout 10)
fi
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -o test/proc_fixture \
       test/proc_fixture.c 2>/dev/null; then
    PF="test/proc_fixture"
    SMOKE=0
    m() {  # m <label> <cmd...>
        local label="$1"; shift
        if "$@"; then
            echo "[OK]   proc_fixture: $label"
        else
            echo "[FAIL] proc_fixture: $label"
            SMOKE=1
        fi
    }
    "$PF" --exit 7
    m "--exit 7 -> exit code 7" [ $? -eq 7 ]
    "$PF" --sleep 50
    m "--sleep 50 -> exit 0" [ $? -eq 0 ]
    N=$("$PF" --stdout 100000 | wc -c)
    m "--stdout 100000 -> 100000 byte" [ "$N" -eq 100000 ]
    P=$("$PF" --stdout 100000 | head -c 3)
    m "--stdout prefix 'AAA'" [ "$P" = "AAA" ]
    N=$("$PF" --stderr 100000 2>&1 1>/dev/null | wc -c)
    m "--stderr 100000 -> 100000 byte" [ "$N" -eq 100000 ]
    N=$("$PF" --both 100000 2>/dev/null | wc -c)
    m "--both 100000 stdout -> 100000 byte" [ "$N" -eq 100000 ]
    N=$("$PF" --both 100000 2>&1 1>/dev/null | wc -c)
    m "--both 100000 stderr -> 100000 byte" [ "$N" -eq 100000 ]
    R=$(printf 'hello world' | "$PF" --read-stdin 5)
    m "--read-stdin 5 -> stdin_read=5" [ "$R" = "stdin_read=5" ]
    R=$(printf 'xy' | "$PF" --read-stdin 99)
    m "--read-stdin 99 (EOF 2) -> stdin_read=2" [ "$R" = "stdin_read=2" ]
    R=$(printf 'x' | "$PF" --never-read-stdin)
    m "--never-read-stdin -> marker, tidak deadlock" [ "$R" = "never_read_stdin" ]
    "$PF" --close-stdout
    m "--close-stdout -> exit 0" [ $? -eq 0 ]
    "$PF" --close-stderr 2>/dev/null
    m "--close-stderr -> exit 0" [ $? -eq 0 ]
    # Bila timeout(1) tak tersedia, spawn smoke tetap harus punya batas
    # (deadlock di logika spawn = hang seluruh suite): pakai sleep pembunuh.
    if [ ${#TMO[@]} -gt 0 ]; then
        "${TMO[@]}" "$PF" --spawn-child --exit 3
        m "--spawn-child --exit 3 -> exit 3" [ $? -eq 3 ]
        "${TMO[@]}" "$PF" --spawn-grandchild --spawn-child --exit 5
        m "--spawn-grandchild chain 3 level -> exit 5" [ $? -eq 5 ]
    else
        echo "[SKIP] proc_fixture: spawn-chain smoke (timeout(1) tak tersedia)"
    fi
    # Pesan "Segmentation fault" ditulis oleh bash (bukan fixture) ke stderr
    # shell-nya sendiri -- grup redirection 2>/dev/null menangkapnya agar
    # output suite bersih.
    { "$PF" --crash >/dev/null 2>&1; } 2>/dev/null
    m "--crash -> exit != 0 (SIGSEGV)" [ $? -ne 0 ]
    R=$(printf 'abc' | "$PF" --output-after-stdin)
    m "--output-after-stdin -> output_after_stdin=3" [ "$R" = "output_after_stdin=3" ]
    R=$(printf 'abc' | "$PF" --stdin-after-output)
    m "--stdin-after-output -> drained=3" [ "$R" = $'stdin_after_output\ndrained=3' ]
    # grep tidak kenal escape \u -> pola byte UTF-8 eksplisit (U+2713 = E2 9C 93).
    "$PF" --unicode-output | grep -q "$(printf '\xe2\x9c\x93')"
    m "--unicode-output memuat multibyte UTF-8" [ $? -eq 0 ]
    "$PF" --binary-output 16 | od -An -tx1 | grep -q '00'
    m "--binary-output 16 memuat byte NUL" [ $? -eq 0 ]
    "$PF" --self-pid | grep -q '^pid=[0-9]'
    m "--self-pid -> pid=<angka>" [ $? -eq 0 ]
    "$PF" --help | grep -q -- '--spawn-grandchild'
    m "--help memuat daftar mode" [ $? -eq 0 ]
    if [ ${#TMO[@]} -gt 0 ]; then
        "${TMO[@]}" "$PF" --hang-after-output >/dev/null 2>&1
        m "--hang-after-output dipotong timeout" [ $? -eq 124 ]
    else
        echo "[SKIP] proc_fixture: --hang-after-output (timeout(1) tak tersedia)"
    fi
    if [ $SMOKE -eq 0 ]; then
        echo "[OK] proc_fixture (PR-005) semua mode smoke lulus"
    else
        echo "[FAIL] proc_fixture (PR-005) smoke mode gagal"
        FAIL=1
    fi
else
    echo "[FAIL] proc_fixture gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 9. proc_deadlock_matrix: PR-006 (P1-T03) deadlock matrix ---
# Matriks kombinasi stdin/stdout/stderr (0/4K/256K/8M) x order
# (read-first/write-first/interleave) x timeout x output cap, dijalankan
# via myc_proc_run terhadap proc_fixture (mode --matrix). Exit criteria
# P1-T03: zero deadlock, zero orphan, zero stuck drain worker, bounded
# memory. Suite memakai default (100 iterasi stress loop); validasi penuh
# 10.000 eksekusi berulang via `proc_deadlock_matrix <fixture> --stress 10000`
# (diverifikasi manual saat penutupan PR-006). External timeout(1) menjaga
# suite bila myc regresi menjadi hang (deadlock = FAIL, bukan hang CI).
PSAPI=""
if $CC -lpsapi -o /dev/null -x c - 2>/dev/null <<'EOF'
#include <psapi.h>
int main(void){return 0;}
EOF
then
    PSAPI="-lpsapi"
fi
if [ -x test/proc_fixture ] || [ -x test/proc_fixture.exe ]; then
    if $CC -O2 -std=c11 -Wall -Wextra -Werror -I. $PTHREAD $PSAPI \
           -o test/proc_deadlock_matrix test/proc_deadlock_matrix.c proc.c alloc.c 2>/dev/null; then
        PFX="test/proc_fixture"
        [ -x "test/proc_fixture.exe" ] && PFX="test/proc_fixture.exe"
        # Log matriks disimpan (bukan dibuang) agar kegagalan memuat
        # konfigurasi lengkap untuk reproduce (prasyarat batch PR-006).
        LOG="test/proc_deadlock_matrix.log"
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 test/proc_deadlock_matrix "$PFX" >"$LOG" 2>&1
            MRC=$?
        else
            test/proc_deadlock_matrix "$PFX" >"$LOG" 2>&1
            MRC=$?
        fi
        if [ $MRC -eq 0 ]; then
            echo "[OK] proc_deadlock_matrix (PR-006 deadlock matrix: zero deadlock)"
        else
            echo "[FAIL] proc_deadlock_matrix (PR-006 deadlock matrix, exit $MRC)"
            grep -E '^\[FAIL\]|FAIL \(|batas waktu' "$LOG" | head -10
            FAIL=1
        fi
    else
        echo "[FAIL] proc_deadlock_matrix gagal dibangun"
        FAIL=1
    fi    else
        echo "[SKIP] proc_deadlock_matrix (proc_fixture tidak terbangun di blok 8)"
    fi

# --- 10. proc_tree_kill: PR-007 (P1-T04) process-tree cleanup ---
# Timeout myc harus membunuh SELURUH pohon proses, bukan hanya child
# langsung: (T1) chain 3-level --spawn-grandchild zero orphan via Toolhelp
# scan (Windows) / verify_descendants (POSIX); (T2) breakaway attempt
# CREATE_BREAKAWAY_FROM_JOB harus DITOLAK job myc (pohon tetap terikat);
# (T3) grandchild di dalam job fixture (nested job) ikut mati; (T4)
# inherited handles: child yang menutup pipe stdout (--spawn-detach) tidak
# menahan drain; (T5) chain normal exit tanpa timeout tetap exit code
# benar. External timeout(1) menjaga suite bila cleanup regresi (orphan
# abadi = FAIL, bukan hang CI).
if [ -x test/proc_fixture ] || [ -x test/proc_fixture.exe ]; then
    if $CC -O2 -std=c11 -Wall -Wextra -Werror -I. -o test/proc_tree_kill \
           test/proc_tree_kill.c proc.c alloc.c 2>/dev/null; then
        PFX="test/proc_fixture"
        [ -x "test/proc_fixture.exe" ] && PFX="test/proc_fixture.exe"
        LOG="test/proc_tree_kill.log"
        if command -v timeout >/dev/null 2>&1; then
            timeout 180 test/proc_tree_kill "$PFX" >"$LOG" 2>&1
            TRC=$?
        else
            test/proc_tree_kill "$PFX" >"$LOG" 2>&1
            TRC=$?
        fi
        if [ $TRC -eq 0 ]; then
            echo "[OK] proc_tree_kill (PR-007 process-tree cleanup: zero orphan)"
        else
            echo "[FAIL] proc_tree_kill (PR-007 process-tree cleanup, exit $TRC)"
            grep -E '^\[FAIL\]|FAIL \(|batas waktu' "$LOG" | head -10
            FAIL=1
        fi
    else
        echo "[FAIL] proc_tree_kill gagal dibangun"
        FAIL=1
    fi
else
    echo "[SKIP] proc_tree_kill (proc_fixture tidak terbangun di blok 8)"
fi

# --- 11. evidence_spoof: PR-008 (P2-T02/INV-006) spoof corpus ---
# Program BERSIH yang sengaja mencetak/menulis teks mirip bukti semantik
# (ASan/UBSan/GCC/Frama-C/Fil-C/marker internal) di stdout/stderr/argv dan
# file report palsu ("<base>.<pid>" di cwd = tmp_dir myc) -> verdict TIDAK
# boleh menjadi violation. Regression hardening PR-008: report sanitizer
# HANYA bukti bila exit != 0 (sebelum fix: file report palsu + exit 0 =
# RUNTIME_VIOLATION PALSU). Fixture smoke standalone + unit test via
# myc_run (clang optional; tanpa clang gate skip dan verdict tetap OK).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -o test/evidence_spoof_fixture \
       tests/evidence_spoof.c 2>/dev/null; then
    FIX="test/evidence_spoof_fixture"
    SMK=0
    "$FIX" >/dev/null 2>&1
    sm() {  # sm <label> <cond> (nama unik: hindari timpa m() blok 8)
        local label="$1"; shift
        if "$@"; then
            echo "[OK]   evidence_spoof_fixture: $label"
        else
            echo "[FAIL] evidence_spoof_fixture: $label"
            SMK=1
        fi
    }
    sm "default -> exit 0" [ $? -eq 0 ]
    "$FIX" --exit 7 >/dev/null 2>&1
    sm "--exit 7 -> exit 7" [ $? -eq 7 ]
    if [ $SMK -eq 0 ]; then
        echo "[OK] evidence_spoof_fixture (PR-008) smoke lulus"
    else
        echo "[FAIL] evidence_spoof_fixture (PR-008) smoke gagal"
        FAIL=1
    fi
else
    echo "[FAIL] evidence_spoof_fixture gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/evidence_spoof \
       test/evidence_spoof.c $SRCS 2>/dev/null; then
    LOG="test/evidence_spoof.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/evidence_spoof >"$LOG" 2>&1
        ERC=$?
    else
        test/evidence_spoof >"$LOG" 2>&1
        ERC=$?
    fi
    if [ $ERC -eq 0 ]; then
        echo "[OK] evidence_spoof (PR-008 spoof corpus: zero false violation)"
    else
        echo "[FAIL] evidence_spoof (PR-008 spoof corpus, exit $ERC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] evidence_spoof gagal dibangun"
    FAIL=1
fi

# --- 12. backend_abuse: PR-009 (P2-T03 tahap 1) parser-abuse corpus ---
# Parser backend (GCC JSON/text diagnostics, sanitizer logs, Frama-C Eva,
# Fil-C, internal JSON + konsumen budget/scenario/calib/cache) di-abuse
# dengan output MALFORMED deterministik dari fake backend
# (tests/backend_fake.c, role gcc/filc-clang/frama-c via env MYC_FAKE_*):
# truncation tiap byte, dup keys, deep nesting, huge numbers, NUL, UTF-8
# invalid, oversized, reordered, unknown enum, garbage, exit-0+garbage.
# Invariant P2-T03: NEVER crash; NEVER promote malformed evidence to
# clean (INV-001) atau ke finding palsu (INV-011). Fixture dibangun
# -Werror -pedantic + smoke; unit test dijalankan dengan MYC_FAKE_GCC
# (fake gcc via req.gcc_program) dan MYC_FAKE_FILC_DIR (fake filc-clang
# di PATH); T6 (Eva) POSIX-only — Windows memakai WSL jadi di-skip.
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -o test/backend_fake \
       tests/backend_fake.c 2>/dev/null; then
    BFK="test/backend_fake"
    [ -x "test/backend_fake.exe" ] && BFK="test/backend_fake.exe"
    BSMK=0
    bf() {  # bf <label> <cmd...> (nama unik: hindari timpa m()/sm())
        local label="$1"; shift
        if "$@"; then
            echo "[OK]   backend_fake: $label"
        else
            echo "[FAIL] backend_fake: $label"
            BSMK=1
        fi
    }
    MYC_FAKE_ROLE=gcc "$BFK" --version >/dev/null 2>&1
    bf "--version (gcc) -> exit 0" [ $? -eq 0 ]
    MYC_FAKE_ROLE=gcc MYC_FAKE_MODE=gcc-json-valid "$BFK" -c >/dev/null 2>&1
    bf "-c gcc-json-valid -> exit 1" [ $? -eq 1 ]
    MYC_FAKE_ROLE=filc "$BFK" --version >/dev/null 2>&1
    bf "--version (filc) -> exit 0" [ $? -eq 0 ]
    # self-copy (filc build): -o target harus menghasilkan binary baru
    # yang identik (fixture menyalin dirinya sendiri).
    TMP_SELF="test/.backend_fake_self"
    MYC_FAKE_ROLE=filc "$BFK" -o "$TMP_SELF" >/dev/null 2>&1
    SELF_OK=0
    # JANGAN pakai `A || B && C` (precedence: A || (B && C) — pada POSIX
    # A benar maka B&&C di-short-circuit, SELF_OK tetap 0). Pakai if eksplisit.
    if [ -x "$TMP_SELF" ] || [ -x "$TMP_SELF.exe" ]; then
        SELF_OK=1
    fi
    bf "-o self-copy menghasilkan binary" [ $SELF_OK -eq 1 ]
    rm -f "$TMP_SELF" "$TMP_SELF.exe"
    if [ $BSMK -eq 0 ]; then
        echo "[OK] backend_fake (PR-009) smoke lulus"
    else
        echo "[FAIL] backend_fake (PR-009) smoke gagal"
        FAIL=1
    fi
else
    echo "[FAIL] backend_fake gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi
if $CC -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/backend_abuse \
       test/backend_abuse.c $SRCS 2>/dev/null; then
    if [ -x "test/backend_fake" ] || [ -x "test/backend_fake.exe" ]; then
        BFK="test/backend_fake"
        [ -x "test/backend_fake.exe" ] && BFK="test/backend_fake.exe"
        # T4 butuh fake filc-clang ter-resolve dari PATH (Windows:
        # filc-clang.exe; POSIX: filc-clang).
        rm -rf test/.backend_fake_filc
        mkdir -p test/.backend_fake_filc
        cp "$BFK" test/.backend_fake_filc/filc-clang 2>/dev/null
        cp "$BFK" test/.backend_fake_filc/filc-clang.exe 2>/dev/null
        LOG="test/backend_abuse.log"
        if command -v timeout >/dev/null 2>&1; then
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.backend_fake_filc" \
                timeout 300 test/backend_abuse >"$LOG" 2>&1
            BRC=$?
        else
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.backend_fake_filc" \
                test/backend_abuse >"$LOG" 2>&1
            BRC=$?
        fi
        if [ $BRC -eq 0 ]; then
            echo "[OK] backend_abuse (PR-009 malformed corpus: never crash/never clean)"
        else
            echo "[FAIL] backend_abuse (PR-009 malformed corpus, exit $BRC)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    else
        # Fixture gagal dibangun di blok 12 atas -> T3/T4 (E2E via fake
        # backend) tidak bisa berjalan; unit test tetap dijalankan tanpa
        # fake env agar T1/T2/T5 tetap menguji parser internal.
        echo "[WARN] backend_abuse dijalankan tanpa fake backend (fixture tidak terbangun)"
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 test/backend_abuse >"$LOG" 2>&1
            BRC=$?
        else
            test/backend_abuse >"$LOG" 2>&1
            BRC=$?
        fi
        if [ $BRC -eq 0 ]; then
            echo "[OK] backend_abuse (PR-009, T1/T2/T5 tanpa fake backend)"
        else
            echo "[FAIL] backend_abuse (PR-009, exit $BRC)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    fi
else
    echo "[FAIL] backend_abuse gagal dibangun"
    FAIL=1
fi

# --- 13. parser_fuzz: PR-010 (P2-T03 tahap 2) parser fuzz harness ---
# Fuzz deterministik (xorshift32, seed tetap 0x9E3779B9; --seed/--iters
# repro). Seed awal = korpus PR-009 + konsumen JSON nyata; mutasi P2-T03:
# bit flip, byte ins/del/set, truncate, splice, dup key, deep nesting
# (melewati JSON_MAX_DEPTH), huge numbers, NUL, UTF-8 invalid, oversized,
# reorder, unknown enum. Target LANGSUNG: json_parse + round-trip
# serialize->parse + json_clone; konsumen budget/calib/scenario/cache
# (fail-closed INV-011). Target E2E: parser GCC/Fil-C/Eva via fake
# backend mode payload-file (byte mutasi APA SAJA). Invariant P2-T03:
# NEVER crash; garbage tanpa marker kanonik TIDAK pernah jadi finding
# (INV-006); exit 0 + teks bukan bukti; marker kanonik + exit!=0 tetap
# terdeteksi (positive control). Seed crash/semantic di-persist ke
# .myc/regression/parser_<sha8>.bin + parser-index.txt (idempoten);
# `--replay` menjalankan ulang semua seed (backstop).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/parser_fuzz test/parser_fuzz.c $SRCS 2>/dev/null; then
    if [ -x "test/backend_fake" ] || [ -x "test/backend_fake.exe" ]; then
        BFK="test/backend_fake"
        [ -x "test/backend_fake.exe" ] && BFK="test/backend_fake.exe"
        # fake filc-clang di PATH dir sendiri (Windows: filc-clang.exe;
        # POSIX: filc-clang); fake frama-c POSIX-only (Windows pakai WSL).
        rm -rf test/.parser_fuzz_filc test/.parser_fuzz_frama
        mkdir -p test/.parser_fuzz_filc
        cp "$BFK" test/.parser_fuzz_filc/filc-clang 2>/dev/null
        cp "$BFK" test/.parser_fuzz_filc/filc-clang.exe 2>/dev/null
        case "$(uname -s 2>/dev/null)" in
            MINGW*|MSYS*|CYGWIN*)
                ;;
            *)
                mkdir -p test/.parser_fuzz_frama
                cp "$BFK" test/.parser_fuzz_frama/frama-c 2>/dev/null
                ;;
        esac
        LOG="test/parser_fuzz.log"
        if command -v timeout >/dev/null 2>&1; then
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.parser_fuzz_filc" \
            MYC_FAKE_FRAMA_DIR="test/.parser_fuzz_frama" \
                timeout 300 test/parser_fuzz --iters 40000 --e2e-iters 8 \
                >"$LOG" 2>&1
            PRC=$?
        else
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.parser_fuzz_filc" \
            MYC_FAKE_FRAMA_DIR="test/.parser_fuzz_frama" \
                test/parser_fuzz --iters 40000 --e2e-iters 8 >"$LOG" 2>&1
            PRC=$?
        fi
        if [ $PRC -eq 0 ]; then
            echo "[OK] parser_fuzz (PR-010 fuzz: zero crash/zero semantic)"
        else
            echo "[FAIL] parser_fuzz (PR-010 fuzz, exit $PRC)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
        # replay backstop: seed tersimpan harus tetap bersih (deteksi
        # parser yang berhenti menangkap crash/semantic seed).
        if command -v timeout >/dev/null 2>&1; then
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.parser_fuzz_filc" \
            MYC_FAKE_FRAMA_DIR="test/.parser_fuzz_frama" \
                timeout 120 test/parser_fuzz --replay >"$LOG" 2>&1
            RRC=$?
        else
            MYC_FAKE_GCC="$BFK" MYC_FAKE_FILC_DIR="test/.parser_fuzz_filc" \
            MYC_FAKE_FRAMA_DIR="test/.parser_fuzz_frama" \
                test/parser_fuzz --replay >"$LOG" 2>&1
            RRC=$?
        fi
        if [ $RRC -eq 0 ]; then
            echo "[OK] parser_fuzz --replay (semua seed tersimpan bersih)"
        else
            echo "[FAIL] parser_fuzz --replay (seed tersimpan masih crash/semantic)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    else
        # Fixture gagal dibangun di blok 12 atas -> E2E tidak bisa jalan;
        # harness tetap dijalankan direct-only (json + konsumen).
        echo "[WARN] parser_fuzz dijalankan tanpa fake backend (fixture tidak terbangun)"
        LOG="test/parser_fuzz.log"
        if command -v timeout >/dev/null 2>&1; then
            timeout 180 test/parser_fuzz --iters 40000 --e2e-iters 0 >"$LOG" 2>&1
            PRC=$?
        else
            test/parser_fuzz --iters 40000 --e2e-iters 0 >"$LOG" 2>&1
            PRC=$?
        fi
        if [ $PRC -eq 0 ]; then
            echo "[OK] parser_fuzz (PR-010, direct-only tanpa fake backend)"
        else
            echo "[FAIL] parser_fuzz (PR-010, exit $PRC)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    fi
else
    echo "[FAIL] parser_fuzz gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 13b. parser_fuzz ASan: deteksi crash memori (bila toolchain ada) ---
# Same harness dibangun dengan -fsanitize=address,undefined: crash parser
# (OOB/UAF/UB di json.c / compile.c / filc.c / prove.c) -> abort ASan
# (exit != 0) -> FAIL. MinGW Windows biasanya tak punya ASan runtime ->
# skip (bukan klaim); Linux CI clang/gcc ASan aktif.
if $CC -fsanitize=address,undefined -o /dev/null -x c - 2>/dev/null <<'EOF'
int main(void){return 0;}
EOF
then
    if $CC -O1 -g -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
           -fsanitize=address,undefined -fno-omit-frame-pointer \
           -o test/parser_fuzz_asan test/parser_fuzz.c $SRCS 2>/dev/null; then
        LOG="test/parser_fuzz_asan.log"
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 test/parser_fuzz_asan --iters 30000 --e2e-iters 6 \
                >"$LOG" 2>&1
            ARC=$?
        else
            test/parser_fuzz_asan --iters 30000 --e2e-iters 6 >"$LOG" 2>&1
            ARC=$?
        fi
        if [ $ARC -eq 0 ]; then
            echo "[OK] parser_fuzz ASan (PR-010: zero memory crash)"
        else
            echo "[FAIL] parser_fuzz ASan (PR-010, exit $ARC)"
            grep -E 'ERROR: AddressSanitizer|runtime error|^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    else
        echo "[FAIL] parser_fuzz ASan gagal dibangun"
        FAIL=1
    fi
else
    echo "[SKIP] parser_fuzz ASan (toolchain ASan tak tersedia)"
fi

# --- 14. cache_key_matrix: PR-011 (MYC-AUDIT-043) cache key spec ---
# Dimension-by-dimension hit/miss via myc_cache_store + myc_cache_try_replay
# langsung (API, tanpa compiler): source, flag gate inti (scenario hash),
# flag gate Fase 5/6 (g2), budget, eksekusi (stdin/timeout/output cap/
# header dir), cwd, tool identity; determinisme + dedup; run stateful
# (assumption ack / require-closed) dan hasil error TIDAK di-store;
# no_cache nonaktif. Gap v1 yang diperbaiki (PR-011) DIUJI sebagai
# MISS: run_stdin / timeout_ms / max_output_bytes / checked_header_dir /
# flag Fase 5/6 (sebelumnya berbagi key = replay stale/lossy).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/cache_key_matrix test/cache_key_matrix.c $SRCS 2>/dev/null; then
    LOG="test/cache_key_matrix.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/cache_key_matrix >"$LOG" 2>&1
        CRC=$?
    else
        test/cache_key_matrix >"$LOG" 2>&1
        CRC=$?
    fi
    if [ $CRC -eq 0 ]; then
        echo "[OK] cache_key_matrix (PR-011 cache key spec: all dims hit/miss)"
    else
        echo "[FAIL] cache_key_matrix (PR-011 cache key spec, exit $CRC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] cache_key_matrix gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 15. atomic_state: PR-012 (MYC-AUDIT-044, P3-T03) atomic .myc writes ---
# Crash-consistency protokol persistensi bersama (persist.c): tulis temp
# + flush + fsync/FlushFileBuffers + rename/replace atomik; temp stale
# dari crash dibersihkan pada write berikutnya. Invariant P3-T03: file
# state selalu OLD valid ATAU NEW valid (tidak pernah setengah). E2E
# semua penulis .myc (cache/ledger/assumptions/calibration/profile/
# regression) lewat API publik + scan akhir NOL leftover *.tmp.*.
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/atomic_state test/atomic_state.c $SRCS 2>/dev/null; then
    LOG="test/atomic_state.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/atomic_state >"$LOG" 2>&1
        ARC=$?
    else
        test/atomic_state >"$LOG" 2>&1
        ARC=$?
    fi
    if [ $ARC -eq 0 ]; then
        echo "[OK] atomic_state (PR-012 atomic .myc writes: old-or-new valid)"
    else
        echo "[FAIL] atomic_state (PR-012 atomic .myc writes, exit $ARC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] atomic_state gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 16. cache_corrupt: PR-013 (MYC-AUDIT-045, P3-T04) corruption recovery ---
# Injeksi korupsi deterministik ke .myc/evidence_cache.json lalu verifikasi
# replay SELALU MISS (reject/quarantine + stderr diagnostic + self-heal
# rewrite) dan bukti dihitung ulang (recompute). Korupsi yang diuji:
# truncated JSON, flipped bits, unknown schema, mismatched hash, duplicate
# entries, stale backend version, malformed timestamp, impossible gate
# state (hash sah pun ditolak lapisan semantik), schema lama tanpa
# entry_sha, non-object entry, garbage file. Invariant P3-T04: NEVER crash
# dan NEVER trust (entry korup tidak pernah di-replay sebagai bukti;
# clamp-to-OK lama pada enum out-of-range kini ditolak). Assert stderr
# diagnostic 'myc: cache:' muncul di log.
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/cache_corrupt test/cache_corrupt.c $SRCS 2>/dev/null; then
    LOG="test/cache_corrupt.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/cache_corrupt >"$LOG" 2>&1
        CRC=$?
    else
        test/cache_corrupt >"$LOG" 2>&1
        CRC=$?
    fi
    if [ $CRC -eq 0 ] && grep -q 'myc: cache:' "$LOG"; then
        echo "[OK] cache_corrupt (PR-013 corruption recovery: reject+recompute)"
    else
        echo "[FAIL] cache_corrupt (PR-013 corruption recovery, exit $CRC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] cache_corrupt gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 17. receipt_vectors: PR-014 (MYC-AUDIT-046) canonical receipt vectors ---
# Byte-string yang di-hash untuk receipt_sha256 dibekukan oleh golden
# vector (dihitung independen via python3 hashlib) + referensi independen
# di dalam test + konsistensi pipeline (receipt hasil myc_reduce_verdict
# == sha256(canonical) == golden). Perubahan format kanonik / enum mapping /
# urutan append = FAIL langsung (bukan menunggu laporan).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/receipt_vectors test/receipt_vectors.c $SRCS 2>/dev/null; then
    LOG="test/receipt_vectors.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/receipt_vectors >"$LOG" 2>&1
        RVC=$?
    else
        test/receipt_vectors >"$LOG" 2>&1
        RVC=$?
    fi
    if [ $RVC -eq 0 ]; then
        echo "[OK] receipt_vectors (PR-014 canonical receipt: golden V1-V4)"
    else
        echo "[FAIL] receipt_vectors (PR-014 canonical receipt, exit $RVC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] receipt_vectors gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 17b. sanloc_test: IDE-1 (qwen-review) Sanitizer Location Extractor ---
# Ekstraksi lokasi pelanggaran runtime (kind/line/fungsi/allocation/snippet)
# dari report sanitizer diuji dengan FIXTURE deterministik (tanpa clang):
# stack/heap/UAF/UBSan + skip frame runtime + remap line inject + anti-
# overclaim. Field sanitizer_location di JSON adalah ADDITIVE (verdict tidak
# pernah berubah).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/sanloc_test test/sanloc_test.c $SRCS 2>/dev/null; then
    LOG="test/sanloc_test.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/sanloc_test >"$LOG" 2>&1
        SLC=$?
    else
        test/sanloc_test >"$LOG" 2>&1
        SLC=$?
    fi
    if [ $SLC -eq 0 ]; then
        echo "[OK] sanloc_test (IDE-1 sanitizer location extractor: semua cek lulus)"
    else
        echo "[FAIL] sanloc_test (IDE-1 sanitizer location extractor, exit $SLC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] sanloc_test gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 17c. regress_replay_test: IDE-4 (qwen-review) regression replay
# pasca-repair (in-process). Replay seluruh corpus terhadap source
# IN-MEMORY (kode baru) via myc_regress_replay_mem: fuzz crash -> seed
# tersimpan otomatis -> replay source buggy = masih gagal, replay source
# fixed = RESOLVED, corpus kosong = 0/0 (anti-overclaim). NON-blocking
# (replay tidak mengubah verdict). Membutuhkan clang (gate fuzz/ASan),
# sama seperti e2e `myc regression run` yang sudah berjalan di CI.
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/regress_replay_test test/regress_replay_test.c $SRCS 2>/dev/null; then
    LOG="test/regress_replay_test.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 test/regress_replay_test >"$LOG" 2>&1
        RPT=$?
    else
        test/regress_replay_test >"$LOG" 2>&1
        RPT=$?
    fi
    if [ $RPT -eq 0 ]; then
        echo "[OK] regress_replay_test (IDE-4 replay pasca-repair: semua cek lulus)"
    else
        echo "[FAIL] regress_replay_test (IDE-4 replay pasca-repair, exit $RPT)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] regress_replay_test gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 17d. runtime_repair_test: IDE-2 (qwen-review) repair template
# RUNTIME_VIOLATION berbasis sanitizer_location. Template deterministik
# (bukan AI): strcpy/strcat -> copy ber-batas + null-terminate (compile-
# clean tanpa <stdio.h>, tanpa -Wformat-truncation), memset/memcpy ->
# clamp ke sizeof/kapasitas malloc, UAF -> NULL-kan setelah free;
# UBSan undefined-behavior -> jujur patched_source NULL + why (anti-
# overclaim). Diuji dgn FIXTURE deterministik (tanpa clang).
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/runtime_repair_test test/runtime_repair_test.c $SRCS 2>/dev/null; then
    LOG="test/runtime_repair_test.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/runtime_repair_test >"$LOG" 2>&1
        RRT=$?
    else
        test/runtime_repair_test >"$LOG" 2>&1
        RRT=$?
    fi
    if [ $RRT -eq 0 ]; then
        echo "[OK] runtime_repair_test (IDE-2 repair template runtime: semua cek lulus)"
    else
        echo "[FAIL] runtime_repair_test (IDE-2 repair template runtime, exit $RRT)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] runtime_repair_test gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 17e. agent_nemo_test: NEMO-1..4 next_check / edits / delta / class ---
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/agent_nemo_test test/agent_nemo_test.c $SRCS 2>/dev/null; then
    LOG="test/agent_nemo_test.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/agent_nemo_test >"$LOG" 2>&1
        ANT=$?
    else
        test/agent_nemo_test >"$LOG" 2>&1
        ANT=$?
    fi
    if [ $ANT -eq 0 ]; then
        echo "[OK] agent_nemo_test (NEMO-1..4 agent protocol: semua cek lulus)"
    else
        echo "[FAIL] agent_nemo_test (NEMO-1..4 agent protocol, exit $ANT)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] agent_nemo_test gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 18. schema_compat: PR-015 (MYC-AUDIT-047) machine schema freeze ---
# Golden file untuk SEMUA skema JSON mesin dibekukan di
# docs/schema-registry.md + test/golden/ (result.v1, agent.v2,
# calibration.v1, evidence cache, scenario.v1, spec.v1, MCP envelope).
# Mengubah skema/field/enum tanpa update golden = FAIL langsung.
if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
       -o test/schema_compat test/schema_compat.c $SRCS 2>/dev/null; then
    LOG="test/schema_compat.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 test/schema_compat >"$LOG" 2>&1
        SCC=$?
    else
        test/schema_compat >"$LOG" 2>&1
        SCC=$?
    fi
    if [ $SCC -eq 0 ]; then
        echo "[OK] schema_compat (PR-015 golden schemas: semua cek lulus)"
    else
        echo "[FAIL] schema_compat (PR-015 golden schemas, exit $SCC)"
        grep -E '^\[FAIL\]' "$LOG" | head -10
        FAIL=1
    fi
else
    echo "[FAIL] schema_compat gagal dibangun (-Werror -pedantic)"
    FAIL=1
fi

# --- 19. mcp_abuse: PR-016 (P4-T04) MCP abuse + soak ---
# mcp.exe (harus dibangun build.bat/build.sh dulu) di-abuse via
# test/mcp_abuse (harness C yang men-link proc.c+json.c): korpus protokol
# malformed deterministik per-kasus + canary ping, huge payload (> cap
# 8 MiB), duplicate request id, notification vs request, EOF/cancellation,
# ordering, dan soak 1.090 request. Invariant P4-T04: stdout TETAP
# protocol-clean (tiap baris respons JSON-RPC 2.0 sah); tidak ada log
# bocor; mcp tidak pernah crash/hang; stderr kosong. External timeout(1)
# menjaga suite bila mcp regresi hang.
if [ -x ./mcp ] || [ -x ./mcp.exe ]; then
    if $CC -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. $PTHREAD \
           -o test/mcp_abuse test/mcp_abuse.c proc.c json.c alloc.c 2>/dev/null; then
        MCPB="./mcp"
        [ -x "./mcp.exe" ] && MCPB="./mcp.exe"
        LOG="test/mcp_abuse.log"
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 test/mcp_abuse "$MCPB" >"$LOG" 2>&1
            MRC=$?
        else
            test/mcp_abuse "$MCPB" >"$LOG" 2>&1
            MRC=$?
        fi
        if [ $MRC -eq 0 ]; then
            echo "[OK] mcp_abuse (PR-016 MCP abuse+soak: protocol-clean)"
        else
            echo "[FAIL] mcp_abuse (PR-016 MCP abuse+soak, exit $MRC)"
            grep -E '^\[FAIL\]' "$LOG" | head -10
            FAIL=1
        fi
    else
        echo "[FAIL] mcp_abuse gagal dibangun (-Werror -pedantic)"
        FAIL=1
    fi
else
    echo "[SKIP] mcp_abuse (mcp/mcp.exe tidak ditemukan - jalankan build.sh/build.bat dulu)"
fi

# --- 20. backends: PR-017 (P5-T01/P5-T02) backend qualification registry ---
# `myc backends` mencantumkan backend dengan tier kebijakan (A = release-
# blocking, B = supported non-blocking, C = best-effort), path executable
# resolv, dan versi EXACT per backend (identitas backend = evidence,
# INV-013). Kualifikasi canary (P5-T02: backend HARUS terbukti hidup
# sebelum klaim bersihnya dipercaya) diverifikasi per backend cepat
# (compile: 2 canary, ~detik) — seluruh swarm 11/11 diuji di
# _ci_linux.sh / _regress_run.bat (Fase 6). NON-blocking: registry tidak
# mengubah verdict verifikasi apa pun.
if [ -x ./myc ] || [ -x ./myc.exe ]; then
    MYCB="./myc"
    [ -x "./myc.exe" ] && MYCB="./myc.exe"
    # CATATAN freeze (PR-017): jumlah "13 backend" adalah registry BEBU
    # — menambah/mengurangi backend di POLICIES[] (canary.c) WAJIB
    # memperbarui cek ini (pola golden, bukan angka ajaib yang tak
    # terjaga).
    if "$MYCB" backends 2>/dev/null | grep -qE "\[OK\] +compile +tier=A.*version="; then
        echo "[OK] backends (PR-017 registry: compile tier A + versi exact)"
    else
        echo "[FAIL] backends (PR-017 registry: compile tier A + versi tidak terlihat)"
        FAIL=1
    fi
    if "$MYCB" backends 2>/dev/null | grep -qE "\[OK\] +run +tier=A.*version="; then
        echo "[OK] backends (PR-017 registry: run tier A + versi exact)"
    else
        echo "[FAIL] backends (PR-017 registry: run tier A + versi tidak terlihat)"
        FAIL=1
    fi
    if "$MYCB" backends 2>/dev/null | grep -q "13 backend terdaftar"; then
        echo "[OK] backends (PR-017 registry: 13 backend terdaftar)"
    else
        echo "[FAIL] backends (PR-017 registry: jumlah backend menyimpang)"
        FAIL=1
    fi
    # Kualifikasi canary per backend (P5-T02): `myc backends --canary`
    # menjalankan canary SEMUA backend yang punya canary (11 canary;
    # mutate/exhaustive lambat) lalu periksa compile PASS. Satu run ke
    # log tmp (guard timeout(1) eksternal agar canary yang hang tidak
    # menggantung suite), grep dari log yang sama.
    BLOG="test/.backends_canary.log"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 "$MYCB" backends --canary > "$BLOG" 2>&1
        BKC=$?
    else
        "$MYCB" backends --canary > "$BLOG" 2>&1
        BKC=$?
    fi
    if [ $BKC -eq 0 ] && grep -q "compile.*-> PASS" "$BLOG"; then
        echo "[OK] backends (PR-017 canary qualification: compile PASS)"
    else
        echo "[FAIL] backends (PR-017 canary qualification: compile GAGAL, exit $BKC)"
        grep -E '^\[FAIL\]' "$BLOG" | head -5
        FAIL=1
    fi
    rm -f "$BLOG"
else
    echo "[SKIP] backends (myc/myc.exe tidak ditemukan - jalankan build.sh/build.bat dulu)"
fi

# --- 21. limits: PR-018 (P7-T01) resource ceilings ---
# `myc limits` mencantumkan tabel kebenaran resource limit + kelas
# enforcement (HARD = ingress fail-fast, soft = cap + debt). Jumlah "29"
# adalah FREEZE registry (pola golden backends blok 20): menambah/
# mengurangi baris di LIMITS[] (limit.c) WAJIB memperbarui cek ini.
# Debt tipe resource_limit diuji lewat jalur NYATA driver_bounded
# (ok_driver_bounded.c --driver): NON-blocking (verdict OK) lalu
# --require-complete menaikkan ke INCONCLUSIVE (pola 9.10).
if [ -x ./myc ] || [ -x ./myc.exe ]; then
    MYCB="./myc"
    [ -x "./myc.exe" ] && MYCB="./myc.exe"
    if "$MYCB" limits 2>/dev/null | grep -qE "\[HARD\] +max_source_bytes +1048576"; then
        echo "[OK] limits (PR-018: max_source_bytes HARD 1 MiB)"
    else
        echo "[FAIL] limits (PR-018: max_source_bytes HARD tidak terlihat)"
        FAIL=1
    fi
    if "$MYCB" limits 2>/dev/null | grep -qE "\[soft\] +max_driver_records"; then
        echo "[OK] limits (PR-018: max_driver_records soft)"
    else
        echo "[FAIL] limits (PR-018: max_driver_records soft tidak terlihat)"
        FAIL=1
    fi
    if "$MYCB" limits 2>/dev/null | grep -q "29 resource limit terdefinisi"; then
        echo "[OK] limits (PR-018: 29 resource limit terdefinisi)"
    else
        echo "[FAIL] limits (PR-018: jumlah resource limit menyimpang)"
        FAIL=1
    fi
    # JSON schema myc.limits.v1: schema + count + id pertama.
    if "$MYCB" limits --json 2>/dev/null | grep -q '"schema": "myc.limits.v1"' &&
       "$MYCB" limits --json 2>/dev/null | grep -q '"id": "max_source_bytes"'; then
        echo "[OK] limits --json (PR-018: schema myc.limits.v1 + id)"
    else
        echo "[FAIL] limits --json (PR-018: schema/id tidak terlihat)"
        FAIL=1
    fi
    # Flag tak dikenal fail-fast exit 2 (pola backends).
    "$MYCB" limits --bogus > /dev/null 2>&1
    if [ $? -eq 2 ]; then
        echo "[OK] limits (PR-018: flag tak dikenal fail-fast exit 2)"
    else
        echo "[FAIL] limits (PR-018: flag tak dikenal tidak fail-fast)"
        FAIL=1
    fi
    # Debt TERTYPE MYC-INCOMPLETE-RESOURCE-LIMIT di jalur NYATA
    # driver_bounded (ok_driver_bounded.c --driver): NON-blocking
    # (verdict TETAP OK tanpa --require-complete).
    if "$MYCB" check test/fixtures/ok_driver_bounded.c --driver 2>&1 |
           grep -q "MYC-INCOMPLETE-RESOURCE-LIMIT"; then
        echo "[OK] limits (PR-018: debt resource_limit via driver_bounded)"
    else
        echo "[FAIL] limits (PR-018: debt resource_limit tidak muncul)"
        FAIL=1
    fi
    if "$MYCB" check test/fixtures/ok_driver_bounded.c --driver 2>&1 |
           grep -q "verdict:   OK"; then
        echo "[OK] limits (PR-018: debt NON-blocking, verdict OK)"
    else
        echo "[FAIL] limits (PR-018: debt NON-blocking dilanggar)"
        FAIL=1
    fi
    # --require-complete menaikkan ke INCONCLUSIVE (pola 9.10).
    if "$MYCB" check test/fixtures/ok_driver_bounded.c --driver --require-complete 2>&1 |
           grep -q "verdict:   INCONCLUSIVE"; then
        echo "[OK] limits (PR-018: --require-complete menaikkan ke INCONCLUSIVE)"
    else
        echo "[FAIL] limits (PR-018: require-complete tidak menaikkan verdict)"
        FAIL=1
    fi
else
    echo "[SKIP] limits (myc/myc.exe tidak ditemukan - jalankan build.sh/build.bat dulu)"
fi

# --- 22. allocator: PR-019 (P7-T02) wrapper formal myc_malloc/calloc/realloc/free ---
# SEMUA alokasi source myc harus lewat wrapper formal (produksi map ke libc,
# test build fail Nth via MYC_ALLOC_TEST). Sisa malloc/calloc/realloc/free
# MENTAH hanya boleh ada di alloc.c (implementasi wrapper) dan komentar.
# Cek: panggilan mentah yang dihapus komentar/string, dan file != alloc.c.
if grep -nE '\b(malloc|calloc|realloc|free)[[:space:]]*\(' *.c 2>/dev/null | \
       grep -vE '^alloc\.c:' | \
       grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' | \
       grep -vE ':[0-9]+:.*"(.*\b(free|malloc|calloc|realloc)\b.*)"' | \
       grep -vE '\b(json_free|myc_[a-z_]*_free|min_free|sha256_free)\(' > /dev/null 2>&1; then
    echo "[FAIL] allocator (PR-019: masih ada panggilan malloc/calloc/realloc/free mentah di source)"
    FAIL=1
else
    echo "[OK] allocator (PR-019: seluruh alokasi source lewat myc_malloc/calloc/realloc/free)"
fi
# alloc.c dengan MYC_ALLOC_TEST harus menyediakan hook nth-failure
# (myc_alloc_set_fail_after) dan passthrough produksi tanpa makro aneh.
if grep -q "myc_alloc_set_fail_after" alloc.c && grep -q "MYC_ALLOC_TEST" alloc.c; then
    echo "[OK] allocator (PR-019: alloc.c menyediakan hook nth-failure + produksi passthrough)"
else
    echo "[FAIL] allocator (PR-019: alloc.c hook/MYC_ALLOC_TEST tidak ada)"
    FAIL=1
fi

rm -f test/proc_flood test/proc_flood.exe test/oom_guards test/oom_guards.exe \
      test/oom_alloc test/oom_alloc.exe test/stress_threads test/stress_threads.exe \
      test/verify_descendants test/verify_descendants.exe \
      test/audit_lampiran test/audit_lampiran.exe \
      test/audit_lampiran_asan test/audit_lampiran_asan.exe \
      test/reducer_exhaustive test/reducer_exhaustive.exe \
      test/proc_fixture test/proc_fixture.exe \
      test/proc_deadlock_matrix test/proc_deadlock_matrix.exe \
      test/proc_deadlock_matrix.log \
      test/proc_tree_kill test/proc_tree_kill.exe \
      test/proc_tree_kill.log \
      test/evidence_spoof test/evidence_spoof.exe \
      test/evidence_spoof_fixture test/evidence_spoof_fixture.exe \
      test/evidence_spoof.log \
      test/backend_fake test/backend_fake.exe \
      test/backend_abuse test/backend_abuse.exe \
      test/backend_abuse.log \
      test/parser_fuzz test/parser_fuzz.exe \
      test/parser_fuzz_asan test/parser_fuzz_asan.exe \
      test/parser_fuzz.log test/parser_fuzz_asan.log \
      test/cache_key_matrix test/cache_key_matrix.exe \
      test/cache_key_matrix.log \
      test/atomic_state test/atomic_state.exe \
      test/atomic_state.log \
      test/cache_corrupt test/cache_corrupt.exe \
      test/cache_corrupt.log \
      test/receipt_vectors test/receipt_vectors.exe \
      test/receipt_vectors.log \
      test/sanloc_test test/sanloc_test.exe \
      test/sanloc_test.log \
      test/regress_replay_test test/regress_replay_test.exe \
      test/regress_replay_test.log \
      test/agent_nemo_test test/agent_nemo_test.exe \
      test/agent_nemo_test.log \
      test/schema_compat test/schema_compat.exe \
      test/schema_compat.log \
      test/mcp_abuse test/mcp_abuse.exe \
      test/mcp_abuse.log \
      test/.backends_canary.log \
      test/.parser_fuzz_payload.bin test/.parser_fuzz_scen.json
rm -rf test/.backend_fake_filc test/.backend_fake_self test/.backend_fake_self.exe \
      test/.parser_fuzz_filc test/.parser_fuzz_frama
rm -rf test/.cache_key_tmp test/.atomic_tmp test/.cache_corrupt_tmp
rm -rf test/.schema_compat_tmp test/.mcp_abuse_tmp

# --- 6c. Fil-C gate (jika filc-clang tersedia di PATH) ---
if command -v filc-clang >/dev/null 2>&1 && [ -x ./myc ]; then
    # MYC-AUDIT-023: jangan pakai run_built (cek EXIT code) untuk fixture
    # bad_filc_oob — verdict FILC_VIOLATION memang keluar exit 1 (benar).
    # Assert via output, bukan exit code.
    if ./myc check test/fixtures/ok_filc.c --filc 2>&1 | grep -q "verdict:   OK"; then
        echo "[OK] filc ok_filc --filc (L5 FILC)"
    else
        echo "[FAIL] filc ok_filc --filc (L5 FILC)"
        FAIL=1
    fi
    if ./myc check test/fixtures/bad_filc_oob.c --filc --run 2>&1 | grep -q "FILC_VIOLATION"; then
        echo "[OK] filc bad_filc_oob --filc --run (FILC_VIOLATION)"
    else
        echo "[FAIL] filc bad_filc_oob --filc --run (FILC_VIOLATION)"
        FAIL=1
    fi
    # MYC-AUDIT-024 (roadmap 7.7): version identity + robust report parser
    # (per-case scope). Parser struktural: baris kanonik "[pid] filc panic:",
    # detail message + lokasi origin (file:line:col: func) tiap panic.
    if ./myc check test/fixtures/ok_filc.c --filc 2>&1 | grep -q "version: clang version"; then
        echo "[OK] filc version identity (7.7)"
    else
        echo "[FAIL] filc version identity (7.7)"
        FAIL=1
    fi
    if ./myc check test/fixtures/bad_filc_oob.c --filc 2>&1 | grep -q "case #1:"; then
        echo "[OK] filc per-case scope (7.7)"
    else
        echo "[FAIL] filc per-case scope (7.7)"
        FAIL=1
    fi
else
    echo "[SKIP] filc-clang tidak tersedia di PATH atau myc binary tidak ditemukan"
fi

rm -f test/filc_test test/filc_test.exe

echo "audit018: $([ $FAIL -eq 0 ] && echo SELESAI OK || echo GAGAL)"
exit $FAIL
