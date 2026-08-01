/*
 * sha256.h -- Implementasi SHA-256 minimal, tanpa dependensi eksternal.
 */
#ifndef MYC_SHA256_H
#define MYC_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);

/* One-shot: hash data ke out[32], lalu tulis hex (65 byte) ke hex_out. */
void sha256_hex(const void *data, size_t len, char hex_out[65]);

#endif /* MYC_SHA256_H */
