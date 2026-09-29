// Test version that matches aes_cl2.c benchmark methodology exactly
// gcc -std=c99 -O3 -march=silvermont -mtune=silvermont -maes -flto -fomit-frame-pointer -funroll-loops -static -o aes-atom-test aes-atom-test.c -lrt

#define _GNU_SOURCE
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32
#define SIZE (4*(1024 * 1024)) // 4 MB like aes_cl2

// Key expansion from aes.c (Atom optimized version)
static void aes256_key_expansion_atom(const uint8_t *key, __m128i *round_keys) {
    __m128i tmp1, tmp2, tmp3;
    tmp1 = _mm_loadu_si128((const __m128i *)key);
    tmp3 = _mm_loadu_si128((const __m128i *)(key + 16));
    round_keys[0] = tmp1;
    round_keys[1] = tmp3;

    const uint8_t rcon[] = {1, 2, 4, 8, 16, 32, 64};

    for (int i = 0; i < 7; ++i) {
        tmp2 = _mm_aeskeygenassist_si128(tmp3, rcon[i]);
        tmp2 = _mm_shuffle_epi32(tmp2, 0xff);
        tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));
        tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));
        tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));
        tmp1 = _mm_xor_si128(tmp1, tmp2);
        round_keys[2 * i + 2] = tmp1;

        tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
        tmp2 = _mm_shuffle_epi32(tmp2, 0xaa);
        tmp3 = _mm_xor_si128(tmp3, _mm_slli_si128(tmp3, 4));
        tmp3 = _mm_xor_si128(tmp3, _mm_slli_si128(tmp3, 4));
        tmp3 = _mm_xor_si128(tmp3, _mm_slli_si128(tmp3, 4));
        tmp3 = _mm_xor_si128(tmp3, tmp2);
        round_keys[2 * i + 3] = tmp3;
    }
}

// 2-way unrolled from aes.c
static inline void aes256_encrypt_2blocks_unrolled(__m128i *b0, __m128i *b1, const __m128i *rk) {
    *b0 = _mm_xor_si128(*b0, rk[0]);
    *b1 = _mm_xor_si128(*b1, rk[0]);
    
    *b0 = _mm_aesenc_si128(*b0, rk[1]);
    *b1 = _mm_aesenc_si128(*b1, rk[1]);
    *b0 = _mm_aesenc_si128(*b0, rk[2]);
    *b1 = _mm_aesenc_si128(*b1, rk[2]);
    *b0 = _mm_aesenc_si128(*b0, rk[3]);
    *b1 = _mm_aesenc_si128(*b1, rk[3]);
    *b0 = _mm_aesenc_si128(*b0, rk[4]);
    *b1 = _mm_aesenc_si128(*b1, rk[4]);
    *b0 = _mm_aesenc_si128(*b0, rk[5]);
    *b1 = _mm_aesenc_si128(*b1, rk[5]);
    *b0 = _mm_aesenc_si128(*b0, rk[6]);
    *b1 = _mm_aesenc_si128(*b1, rk[6]);
    *b0 = _mm_aesenc_si128(*b0, rk[7]);
    *b1 = _mm_aesenc_si128(*b1, rk[7]);
    *b0 = _mm_aesenc_si128(*b0, rk[8]);
    *b1 = _mm_aesenc_si128(*b1, rk[8]);
    *b0 = _mm_aesenc_si128(*b0, rk[9]);
    *b1 = _mm_aesenc_si128(*b1, rk[9]);
    *b0 = _mm_aesenc_si128(*b0, rk[10]);
    *b1 = _mm_aesenc_si128(*b1, rk[10]);
    *b0 = _mm_aesenc_si128(*b0, rk[11]);
    *b1 = _mm_aesenc_si128(*b1, rk[11]);
    *b0 = _mm_aesenc_si128(*b0, rk[12]);
    *b1 = _mm_aesenc_si128(*b1, rk[12]);
    *b0 = _mm_aesenc_si128(*b0, rk[13]);
    *b1 = _mm_aesenc_si128(*b1, rk[13]);
    
    *b0 = _mm_aesenclast_si128(*b0, rk[14]);
    *b1 = _mm_aesenclast_si128(*b1, rk[14]);
}

// Single block unrolled from aes.c  
static inline __m128i aes256_encrypt_block_unrolled(__m128i block, const __m128i *rk) {
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    block = _mm_aesenclast_si128(block, rk[14]);
    return block;
}

// CTR function from aes.c but modified to match aes_cl2 style - IN-PLACE operation
static void aes256_ctr_encrypt_inplace(uint8_t *buf, size_t len, const __m128i *rk, uint8_t *iv) {
    // Load counter once
    uint64_t ctr_low, ctr_high;
    memcpy(&ctr_low, iv + 8, 8);
    memcpy(&ctr_high, iv, 8);
    
    uint8_t *ptr = buf;
    size_t blocks = len / AES_BLOCK_SIZE;
    
    // Process 2 blocks at a time - optimal for Atom
    while (blocks >= 2) {
        // Build counters directly
        __m128i c0 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        __m128i c1 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        // Encrypt both counters
        aes256_encrypt_2blocks_unrolled(&c0, &c1, rk);
        
        // Load, XOR, store - using direct pointer arithmetic (like aes.c optimized)
        __m128i d0 = _mm_loadu_si128((__m128i *)ptr);
        __m128i d1 = _mm_loadu_si128((__m128i *)(ptr + AES_BLOCK_SIZE));
        
        d0 = _mm_xor_si128(d0, c0);
        d1 = _mm_xor_si128(d1, c1);
        
        _mm_storeu_si128((__m128i *)ptr, d0);
        _mm_storeu_si128((__m128i *)(ptr + AES_BLOCK_SIZE), d1);
        
        ptr += 2 * AES_BLOCK_SIZE;
        blocks -= 2;
    }
    
    // Handle remaining block
    if (blocks > 0) {
        __m128i ctr = _mm_set_epi64x(ctr_low, ctr_high);
        __m128i keystream = aes256_encrypt_block_unrolled(ctr, rk);
        __m128i data = _mm_loadu_si128((__m128i *)ptr);
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)ptr, data);
    }
}

static double now_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    
    // Same initialization as aes_cl2
    for (int i = 0; i < AES_256_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) iv[i] = i * 2;

    uint8_t *buf;
    posix_memalign((void **)&buf, 16, SIZE);
    memset(buf, 0xAA, SIZE);

    // KEY EXPANSION DONE ONCE - LIKE AES_CL2.C!
    __m128i round_keys[15];
    aes256_key_expansion_atom(key, round_keys);

    // Warmup
    aes256_ctr_encrypt_inplace(buf, SIZE, round_keys, iv);

    // Benchmark exactly like aes_cl2.c - NO KEY EXPANSION IN LOOP!
    double start = now_sec();
    for (int iter = 0; iter < 100; iter++) {
        aes256_ctr_encrypt_inplace(buf, SIZE, round_keys, iv);
    }
    double end = now_sec();

    printf("AES-256-CTR aes.c implementation (optimized benchmark): %.2f MB/s\n", 
           100 * SIZE / (1024.0 * 1024.0 * (end - start)));

    // Validation print
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
    printf("\n");

    free(buf);
    return 0;
}