/* fixture Fase 6 (regression corpus): fuzz harus menemukan crash
 * div-by-zero di dalam domain kontrak. Source ini BUGGY -- saat
 * dijalankan dengan --fuzz, crash disimpan sebagai seed regression;
 * `myc regression run <file-fixed>` harus melaporkan RESOLVED. */
//@ requires n >= 0 && n <= 3;
int fdiv(int n)
{
    return 10 / (n - 2);
}
