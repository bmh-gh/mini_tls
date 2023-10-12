//
// Created by sascha on 12.10.23.
//

#ifndef MINI_TLS_CHACHA20_H
#define MINI_TLS_CHACHA20_H

#include "types.h"

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_KEY_STREAM_SIZE 64

typedef struct chacha20_state {
    u32 state[16];
    u32 working_state[16];
    u8 key_stream[CHACHA20_KEY_STREAM_SIZE];
    u8 key[CHACHA20_KEY_SIZE];
    u8 nonce[CHACHA20_NONCE_SIZE];
    u32 counter;
} chacha20_ctx;

void init_chacha20_ctx(chacha20_ctx *ctx, u8 key[CHACHA20_KEY_SIZE], u8 nonce[CHACHA20_NONCE_SIZE]);

void chacha20_xcrypt(chacha20_ctx *ctx, u8 *message, u32 m_len);

#endif //MINI_TLS_CHACHA20_H
