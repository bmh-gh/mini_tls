//
// Created by bmh on 12.10.23.
//
#include "../../include/aes_core.h"

#include <string.h>

static inline u8 sub_byte(u8 b) {
    return SBox[b>>4][b&0xF];
}

static u32 g(u8 state[4], u8 rc) {
    u8 new_state[4] = {
            sub_byte(state[1]) ^ rc,
            sub_byte(state[2]),
            sub_byte(state[3]),
            sub_byte(state[0])
    };
    return (*(u32*)new_state);
}

void aes128_key_schedule(aes128_ctx *ctx, const u8 key[16]) {
    memcpy(ctx->ks[0], key, 16);
    u8 w[16];
    memcpy(w, key, 16);
    for(int i = 1; i < AES_128_ROUNDS; i++) {
        *(u32*)w ^= g((w + 12), Rcon[i-1]);
        (*(u32*)(w + 4)) ^= (*(u32*)w);
        (*(u32*)(w + 8)) ^= (*(u32*)(w + 4));
        (*(u32*)(w + 12)) ^= (*(u32*)(w + 8));
        memcpy(ctx->ks[i], w, 16);
    }
}

int main(int args, char **argv) {
    aes128_ctx ctx;
    u8 key[16] = {0};
    aes128_key_schedule(&ctx, key);
    return 0;
}