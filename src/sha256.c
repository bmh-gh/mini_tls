//
// Created by sascha on 12.10.23.
//

#include "../../include/sha256.h"
#include "../../include/types.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ROTL(x,n) ((x << n) | (x >> (32 - n)))
#define ROTR(x,n) ((x >> n) | (x << (32 - n)))

#define SHL(x,n) (x << n)
#define SHR(x,n) (x >> n)

#define Ch(x,y,z) ((x & y) ^ (~x&z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#define MSIZE 64

static inline u32 Sigma0(u32 x) {
return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22);
}

static inline u32 Sigma1(u32 x) {
return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25);
}

static inline u32 sigma0(u32 x) {
return ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3);
}

static inline u32 sigma1(u32 x) {
return ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10);
}

static inline void to_uint32(u8 buffer[64], u32 buff[16]) {
    for (int i = 0; i < 64; i+=4) {
        buff[i/4] = buffer[i] << 24 | buffer[i+1] << 16 | buffer[i+2] << 8 | buffer[i+3];
    }
}

const u32 K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void initState(sha256State_t *state) {
    memset(state->sha256, 0x00, 32);

    state->H[0]=0x6a09e667;
    state->H[1]=0xbb67ae85;
    state->H[2]=0x3c6ef372;
    state->H[3]=0xa54ff53a;
    state->H[4]=0x510e527f;
    state->H[5]=0x9b05688c;
    state->H[6]=0x1f83d9ab;
    state->H[7]=0x5be0cd19;

    state->length = 0;
    state->finalised = 0;
}

void sha256Round(sha256State_t *state);

void sha256Padding(sha256State_t *state) {
    state->message[state->message_length / 4] |= 0x80 << (3 - (state->message_length % 4)) * 8;

    if (state->message_length * 8 + 1 > 448) {
        state->message_length=64;
        sha256Round(state);
        memset(state->message, 0x00, 16 * sizeof(u32));
    }

    state->finalised = 1;
    state->length <<= 3;
    state->message[14] = state->length >> 32;
    state->message[15] = state->length & 0xffffffff;
}

void sha256Round(sha256State_t *state) {
    u32 T1, T2;
    u32 a, b, c, d, e, f, g, h;

    if (state->message_length != 64) {
        sha256Padding(state);
    }

    for (int t = 0; t < 16; t++)
        state->W[t] = state->message[t];

    for (int t = 16; t < 64; t++)
        state->W[t] = sigma1(state->W[t-2]) + state->W[t-7] + sigma0(state->W[t-15]) + state->W[t-16];

    a=state->H[0];
    b=state->H[1];
    c=state->H[2];
    d=state->H[3];
    e=state->H[4];
    f=state->H[5];
    g=state->H[6];
    h=state->H[7];

    for (int t = 0; t < 64; t++) {
        T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + state->W[t];
        T2 = Sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state->H[0] += a;
    state->H[1] += b;
    state->H[2] += c;
    state->H[3] += d;
    state->H[4] += e;
    state->H[5] += f;
    state->H[6] += g;
    state->H[7] += h;
}

void sha256(sha256State_t *state, u8 *buffer, u32 b_len) {
    size_t message_length = 0;
    while(b_len > 0) {
        message_length = (b_len < MSIZE) ? b_len : MSIZE;
        memset(state->message, 0x00, MSIZE);
        to_uint32(buffer, state->message);

        state->message_length = message_length;
        sha256Round(state);

        buffer += message_length;
        b_len -= message_length;
    }
}

void sha256Finalise(sha256State_t *state) {
    if(!state->finalised) {
        memset(state->message, 0x00, 16*sizeof(u32));
        state->message[0] = 0x80000000;
        state->message[14] = state->length >> 32;
        state->message[15] = state->length & 0xffffffff;
        state->finalised = 1;
        sha256Round(state);
    }

    for(int i = 0; i < 8; i++) {
        state->sha256[4*i] = state->H[i] >> 24;
        state->sha256[4*i+1] = state->H[i] >> 16;
        state->sha256[4*i+2] = state->H[i] >> 8;
        state->sha256[4*i+3] = state->H[i] & 0xff;
    }
}