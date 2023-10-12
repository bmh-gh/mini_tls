//
// Created by sascha on 12.10.23.
//

#ifndef MINI_TLS_SHA256_H
#define MINI_TLS_SHA256_H

#include "types.h"

typedef struct sha256State {
    u32 W[64];
    u32 message[16];
    u32 H[8];
    u8 sha256[32];
    u64 length;
    u32 message_length;
    u8 finalised;
} sha256State_t;

void initState(sha256State_t *state);

void sha256(sha256State_t *state, u8 *buffer, u32 b_len);

void sha256Finalise(sha256State_t *state);

#endif //MINI_TLS_SHA256_H
