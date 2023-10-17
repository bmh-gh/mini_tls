//
// Created by bmh on 12.10.23.
//
#include "../../include/aes_core.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

static inline u8 sub_byte(u8 b) {
    return SBox[b>>4][b&0xF];
}

static inline u8 inv_sub_byte(u8 b) {
    return InvSBox[b>>4][b&0xF];
}

static void sub_bytes(u8 state[16]) {
    for(int i = 0; i < 16; i++) {
       state[i] = sub_byte(state[i]);
    }
}

static void inv_sub_bytes(u8 state[16]) {
    for(int i = 0; i < 16; i++) {
        state[i] = inv_sub_byte(state[i]);
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

static void inv_shift_rows(u8 state[16]) {
    u8 tmp = state[1];
    state[1] = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = tmp;

    tmp = state[10];
    state[10] = state[2];
    state[2] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

static u8 x_time(u8 a) {
    if(a & 0x80)
        return (a << 1) ^ 0x1B;
    else
        return a << 1;
}

static inline u8 xx_time(u8 a) {
    return x_time(x_time(a));
}

static inline u8 xxx_time(u8 a) {
    return x_time(x_time(x_time(a)));
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


static inline u8 times_e(u8 a) {
    return xxx_time(a) ^ xx_time(a) ^ x_time(a);
}
static inline u8 times_d(u8 a) {
    return xxx_time(a) ^ xx_time(a) ^ a;
}
static inline u8 times_b(u8 a) {
    return xxx_time(a) ^ x_time(a) ^ a;
}
static inline u8 times_9(u8 a) {
    return xxx_time(a) ^ a;
}

static void inv_mix_columns(u8 state[16]) {
    u8 new_state[16] = {0};
    for (int i = 0; i < 13; i += 4) {
        new_state[i] = times_e(state[i]) ^ times_b(state[i + 1]) ^ times_d(state[i + 2]) ^ times_9(state[i + 3]);
        new_state[i + 1] = times_9(state[i]) ^ times_e(state[i + 1]) ^ times_b(state[i + 2]) ^ times_d(state[i + 3]);
        new_state[i + 2] = times_d(state[i]) ^ times_9(state[i + 1]) ^ times_e(state[i + 2]) ^ times_b(state[i + 3]);
        new_state[i + 3] = times_b(state[i]) ^ times_d(state[i + 1]) ^ times_9(state[i + 2]) ^ times_e(state[i + 3]);
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

static inline void key_addition(u8 state[16], const u8 key[16]) {
    *(u64*) state ^= *(u64*) key;
    *(u64*) (state + 8) ^= *(u64*) (key + 8);
}

void aes128_key_schedule(aes128_ctx *ctx, const u8 key[16]) {
    memcpy(ctx->ks[0], key, 16);
    u8 w[16];
    memcpy(w, key, 16);
    for(int i = 1; i < AES_128_ROUNDS + 1; i++) {
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
    for(int i = 1; i < AES_128_ROUNDS; i++) {
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

void aes128_decipher(aes128_ctx *ctx) {
    u8 state[16];
    memcpy(state, ctx->in, 16);
    key_addition(state, ctx->ks[10]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for(int i = AES_128_ROUNDS - 1; i > 0; i--) {
        key_addition(state, ctx->ks[i]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    key_addition(state, ctx->ks[0]);
    memcpy(ctx->out, state, 16);
}

void aes128_init(aes128_ctx *ctx, u8 key[AES_128_KEY_SIZE]) {
    aes128_key_schedule(ctx, key);
}

static u32 h(u8 state[4]) {
    u8 new_state[4] = {
            sub_byte(state[0]),
            sub_byte(state[1]),
            sub_byte(state[2]),
            sub_byte(state[3])
    };
    return (*(u32*)new_state);
}

void aes256_key_schedule(aes256_ctx *ctx, const u8 key[32]) {
    memcpy(ctx->ks[0], key, 16);
    memcpy(ctx->ks[1], (key + 16), 16);
    u8 w[32];
    memcpy(w, key, 32);
    for(int i = 2; i <= 12; i+=2) {
        *(u32*)w ^= g((w + 28), Rcon[i- (i / 2) - 1]);
        (*(u32*)(w + 4)) ^= (*(u32*)w);
        (*(u32*)(w + 8)) ^= (*(u32*)(w + 4));
        (*(u32*)(w + 12)) ^= (*(u32*)(w + 8));
        (*(u32*)(w + 16)) ^= h((w + 12));
        (*(u32*)(w + 20)) ^= (*(u32*)(w + 16));
        (*(u32*)(w + 24)) ^= (*(u32*)(w + 20));
        (*(u32*)(w + 28)) ^= (*(u32*)(w + 24));
        memcpy(ctx->ks[i], w, 16);
        memcpy(ctx->ks[i + 1], (w + 16), 16);
    }
    *(u32*)w ^= g((w + 28), Rcon[6]);
    (*(u32*)(w + 4)) ^= (*(u32*)w);
    (*(u32*)(w + 8)) ^= (*(u32*)(w + 4));
    (*(u32*)(w + 12)) ^= (*(u32*)(w + 8));
    memcpy(ctx->ks[14], w, 16);
}


void aes256_init(aes256_ctx *ctx, u8 key[AES_256_KEY_SIZE]) {
    aes256_key_schedule(ctx, key);
}
void aes256_cipher(aes256_ctx *ctx) {
    u8 state[16];
    memcpy(state, ctx->in, 16);
    key_addition(state, ctx->ks[0]);
    for(int i = 1; i < AES_256_ROUNDS; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        key_addition(state, ctx->ks[i]);
    }
    sub_bytes(state);
    shift_rows(state);
    key_addition(state, ctx->ks[14]);
    memcpy(ctx->out, state, 16);
}
void aes256_decipher(aes256_ctx *ctx) {
    u8 state[16];
    memcpy(state, ctx->in, 16);
    key_addition(state, ctx->ks[14]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for(int i = AES_256_ROUNDS - 1; i > 0; i--) {
        key_addition(state, ctx->ks[i]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    key_addition(state, ctx->ks[0]);
    memcpy(ctx->out, state, 16);
}
