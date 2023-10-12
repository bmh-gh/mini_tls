//
// Created by sascha on 12.10.23.
//

#include "../include/chacha20.h"
#include <string.h>

#ifndef ROUNDS
#define ROUNDS 10
#endif

#ifndef CHACHA20_MESSAGE_SIZE
#define CHACHA20_MESSAGE_SIZE CHACHA20_KEY_STREAM_SIZE
#endif

static inline void ROTL(u32 *x, u32 n) {
    *x = (*x << n) | (*x >> (32 - n));
}

void init_chacha20_ctx(chacha20_ctx *ctx, u8 key[CHACHA20_KEY_SIZE], u8 nonce[CHACHA20_NONCE_SIZE]) {
    memcpy(ctx->key, key, CHACHA20_KEY_SIZE);
    memcpy(ctx->nonce, nonce, CHACHA20_NONCE_SIZE);
    memset(ctx->key_stream, 0x00, CHACHA20_KEY_STREAM_SIZE);
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

static void chacha20_block(chacha20_ctx *ctx) {
    ctx->state[12] = ctx->counter;
    memcpy(ctx->working_state, ctx->state, 16*sizeof(uint32_t));

    for(int i = 0; i < ROUNDS; i++) {
        quarter_round(&ctx->working_state[0], &ctx->working_state[4], &ctx->working_state[ 8], &ctx->working_state[12]);
        quarter_round(&ctx->working_state[1], &ctx->working_state[5], &ctx->working_state[ 9], &ctx->working_state[13]);
        quarter_round(&ctx->working_state[2], &ctx->working_state[6], &ctx->working_state[10], &ctx->working_state[14]);
        quarter_round(&ctx->working_state[3], &ctx->working_state[7], &ctx->working_state[11], &ctx->working_state[15]);

        quarter_round(&ctx->working_state[0], &ctx->working_state[5], &ctx->working_state[10], &ctx->working_state[15]);
        quarter_round(&ctx->working_state[1], &ctx->working_state[6], &ctx->working_state[11], &ctx->working_state[12]);
        quarter_round(&ctx->working_state[2], &ctx->working_state[7], &ctx->working_state[ 8], &ctx->working_state[13]);
        quarter_round(&ctx->working_state[3], &ctx->working_state[4], &ctx->working_state[ 9], &ctx->working_state[14]);
    }

    u32 kw = 0;
    for(int i = 0; i < 16; i++) {
        kw = ctx->state[i] + ctx->working_state[i];

        ctx->key_stream[4 * i] = kw & 0xff;
        ctx->key_stream[4 * i + 1] = kw >> 8;
        ctx->key_stream[4 * i + 2] = kw >> 16;
        ctx->key_stream[4 * i + 3] = kw >> 24;
    }
}

void chacha20_xcrypt(chacha20_ctx *ctx, u8 *message, u32 m_len) {
    size_t message_length = 0;
    while(m_len > 0) {
        message_length = (m_len < CHACHA20_MESSAGE_SIZE) ? m_len : CHACHA20_MESSAGE_SIZE;

        chacha20_block(ctx);
        for(int i = 0; i < message_length; i++) {
            message[i] ^= ctx->key_stream[i];
        }

        ctx->counter++;
        m_len -= message_length;
        message += message_length;
    }
}