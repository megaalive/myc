/* contract_wide.c -- fixture contract-delta (Fase 2) baseline.
 * Domain luas. Bandingkan dengan contract_narrow.c -> NARROWED. */
//@ requires n >= 0;
//@ ensures  r >= 0;
int f(int n) { return n; }
