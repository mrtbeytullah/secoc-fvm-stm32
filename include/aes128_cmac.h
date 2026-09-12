#ifndef AES128_CMAC_H
#define AES128_CMAC_H

#include <stdint.h>
#include <stddef.h>

#define AES128_BLOCK_SIZE 16
#define AES128_KEY_SIZE   16

typedef struct {
    uint8_t round_keys[176];
} aes128_ctx_t;

typedef struct {
    aes128_ctx_t aes_ctx;
    uint8_t k1[AES128_BLOCK_SIZE];
    uint8_t k2[AES128_BLOCK_SIZE];
} aes128_cmac_ctx_t;

void aes128_init(aes128_ctx_t *ctx, const uint8_t *key);
void aes128_encrypt_block(const aes128_ctx_t *ctx, const uint8_t *in, uint8_t *out);

void aes128_cmac_init(aes128_cmac_ctx_t *ctx, const uint8_t *key);
void aes128_cmac_compute(const aes128_cmac_ctx_t *ctx, const uint8_t *msg, size_t len, uint8_t *mac);
uint32_t aes128_cmac_compute_tag32(const aes128_cmac_ctx_t *ctx, const uint8_t *msg, size_t len);

#endif
