/* contract_narrow.c -- fixture contract-delta (Fase 2).
 * Pasangan: contract_wide.c (baseline) -> contract_narrow.c (patch).
 * Patch MENYEMPITKAN domain requires -> klasifikasi NARROWED
 * (scope-laundering: repair yang menghilangkan bug dengan mempersempit
 * domain wajib ditolak di repair transaction). */
//@ requires n >= 0 && n <= 100;
//@ ensures  r >= 0;
int f(int n) { return n; }
