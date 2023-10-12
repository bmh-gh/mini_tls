//
// Created by sascha on 12.10.23.
//

#include "../include/chacha20.h"
#include <string.h>

#ifndef ROUNDS
#define ROUNDS 10
#endif

static inline void ROTL(u32 *x, u32 n) {
    *x = (*x << n) | (*x >> (32 - n));
}

void init_chacha20_ctx(chacha20_ctx *ctx, u8 key[CHACHA20_KEY_SIZE], u8 nonce[CHACHA20_NONCE_SIZE]) {
    memcpy(ctx->key, key, CHACHA20_KEY_SIZE);
    memcpy(ctx->nonce, nonce, CHACHA20_NONCE_SIZE);
    ctx->counter = 1;

    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;

    memcpy(ctx->state+4, key, sizeof(u32));
    memcpy(ctx->state+5, key+4, sizeof(u32));
    memcpy(ctx->state+6, key+8, sizeof(u32));
    memcpy(ctx->state+7, key+12, sizeof(u32));
    memcpy(ctx->state+8, key+16, sizeof(u32));
    memcpy(ctx->state+9, key+20, sizeof(u32));
    memcpy(ctx->state+10, key+24, sizeof(u32));
    memcpy(ctx->state+11, key+28, sizeof(u32));

    ctx->state[12] = ctx->counter;

    memcpy(ctx->state+13, nonce, sizeof(u32));
    memcpy(ctx->state+14, nonce+4, sizeof(u32));
    memcpy(ctx->state+15, nonce+8, sizeof(u32));
}

static void quarter_round(u32 *a, u32 *b, u32 *c, u32 *d) {
    *a += *b,  *d ^= *a,  ROTL(d, 16);
    *c += *d,  *b ^= *c,  ROTL(b, 12);
    *a += *b,  *d ^= *a,  ROTL(d, 8);
    *c += *d,  *b ^= *c,  ROTL(b, 7);
}

void chacha20_block(chacha20_ctx *ctx) {
    memcpy(ctx->old_state, ctx->state, 16*sizeof(uint32_t));

    for(int i = 0; i < ROUNDS; i++) {
        quarter_round(&ctx->state[0], &ctx->state[4], &ctx->state[ 8], &ctx->state[12]);
        quarter_round(&ctx->state[1], &ctx->state[5], &ctx->state[ 9], &ctx->state[13]);
        quarter_round(&ctx->state[2], &ctx->state[6], &ctx->state[10], &ctx->state[14]);
        quarter_round(&ctx->state[3], &ctx->state[7], &ctx->state[11], &ctx->state[15]);

        quarter_round(&ctx->state[0], &ctx->state[5], &ctx->state[10], &ctx->state[15]);
        quarter_round(&ctx->state[1], &ctx->state[6], &ctx->state[11], &ctx->state[12]);
        quarter_round(&ctx->state[2], &ctx->state[7], &ctx->state[ 8], &ctx->state[13]);
        quarter_round(&ctx->state[3], &ctx->state[4], &ctx->state[ 9], &ctx->state[14]);
    }

    for(int i = 0; i < 16; i++)
        ctx->state[i] += ctx->old_state[i];
}