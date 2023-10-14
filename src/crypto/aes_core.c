//
// Created by bmh on 12.10.23.
//
#include "../../include/aes_core.h"

#include <string.h>
#include <stdio.h>

static inline u8 sub_byte(u8 b) {
    return SBox[b>>4][b&0xF];
}

static void sub_bytes(u8 state[16]) {
    for(int i = 0; i < 16; i++) {
       state[i] = sub_byte(state[i]);
    }
}

static void shift_rows(u8 state[16]) {
    u8 tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

static u8 x_time(u8 a) {
    if(a & 0x80)
        return (a << 1) ^ 0x1B;
    else
        return a << 1;
}

static void mix_columns(u8 state[16]) {
    u8 new_state[16] = {0};
    for(int i = 0; i < 13; i += 4) {
        new_state[i] = x_time(state[i]) ^ (x_time(state[i + 1]) ^ state[i + 1]) ^ state[i + 2] ^ state[i + 3];
        new_state[i + 1] = state[i] ^ x_time(state[i + 1]) ^ (x_time(state[i + 2]) ^ state[i + 2]) ^ state[i + 3];
        new_state[i + 2] = state[i] ^ state[i + 1] ^ x_time(state[i + 2]) ^ (x_time( state[i + 3]) ^ state[i + 3]);
        new_state[i + 3] = (x_time(state[i]) ^ state[i]) ^ state[i + 1] ^ state[i + 2] ^ x_time(state[i + 3]);
    }
    memcpy(state, new_state, 16);
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

static inline void key_addition(u8 state[16], u8 key[16]) {
    *(u64*) state ^= *(u64*) key;
    *(u64*) (state + 8) ^= *(u64*) (key + 8);
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

void aes128_cipher(aes128_ctx *ctx) {
    u8 state[16];
    memcpy(state, ctx->in, 16);
    key_addition(state, ctx->ks[0]);
    for(int i = 1; i < AES_128_ROUNDS - 1; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        key_addition(state, ctx->ks[i]);
    }
    sub_bytes(state);
    shift_rows(state);
    key_addition(state, ctx->ks[10]);
    memcpy(ctx->out, state, 16);
}