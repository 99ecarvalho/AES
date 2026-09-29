#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32
#define SIZE (1024 * 1024) // 1 MB for benchmark

// Expand AES-256 key using AES-NI intrinsics
static void aes256_key_expansion(const uint8_t *key, __m128i *round_keys) {
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

// Encrypt 4 blocks in parallel - massive speedup from instruction-level parallelism
static inline void aes256_encrypt_4blocks(
    __m128i *b0, __m128i *b1, __m128i *b2, __m128i *b3,
    const __m128i *rk)
{
    *b0 = _mm_xor_si128(*b0, rk[0]);
    *b1 = _mm_xor_si128(*b1, rk[0]);
    *b2 = _mm_xor_si128(*b2, rk[0]);
    *b3 = _mm_xor_si128(*b3, rk[0]);
    
    for (int i = 1; i < 14; ++i) {
        *b0 = _mm_aesenc_si128(*b0, rk[i]);
        *b1 = _mm_aesenc_si128(*b1, rk[i]);
        *b2 = _mm_aesenc_si128(*b2, rk[i]);
        *b3 = _mm_aesenc_si128(*b3, rk[i]);
    }
    
    *b0 = _mm_aesenclast_si128(*b0, rk[14]);
    *b1 = _mm_aesenclast_si128(*b1, rk[14]);
    *b2 = _mm_aesenclast_si128(*b2, rk[14]);
    *b3 = _mm_aesenclast_si128(*b3, rk[14]);
}

// Increment counter by 1 (little-endian)
static inline __m128i increment_counter(__m128i ctr) {
    const __m128i one = _mm_set_epi64x(0, 1);
    const __m128i mask = _mm_set_epi64x(0, 0xFFFFFFFFFFFFFFFFULL);
    
    __m128i carry = _mm_add_epi64(ctr, one);
    __m128i overflow = _mm_cmpeq_epi64(_mm_and_si128(ctr, mask), mask);
    overflow = _mm_shuffle_epi32(overflow, _MM_SHUFFLE(1, 0, 3, 2));
    __m128i high_add = _mm_and_si128(overflow, one);
    return _mm_add_epi64(carry, high_add);
}

// CTR mode encryption with 4-way parallelism
static void aes256_ctr_encrypt(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *rk, uint8_t *iv)
{
    __m128i ctr = _mm_loadu_si128((__m128i *)iv);
    size_t blocks = len / AES_BLOCK_SIZE;
    size_t i = 0;
    
    // Process 4 blocks at a time for maximum throughput
    while (i + 4 <= blocks) {
        __m128i c0 = ctr;
        ctr = increment_counter(ctr);
        __m128i c1 = ctr;
        ctr = increment_counter(ctr);
        __m128i c2 = ctr;
        ctr = increment_counter(ctr);
        __m128i c3 = ctr;
        ctr = increment_counter(ctr);
        
        // Encrypt 4 counters in parallel
        aes256_encrypt_4blocks(&c0, &c1, &c2, &c3, rk);
        
        // XOR with plaintext
        __m128i d0 = _mm_loadu_si128((__m128i *)(in + (i + 0) * AES_BLOCK_SIZE));
        __m128i d1 = _mm_loadu_si128((__m128i *)(in + (i + 1) * AES_BLOCK_SIZE));
        __m128i d2 = _mm_loadu_si128((__m128i *)(in + (i + 2) * AES_BLOCK_SIZE));
        __m128i d3 = _mm_loadu_si128((__m128i *)(in + (i + 3) * AES_BLOCK_SIZE));
        
        d0 = _mm_xor_si128(d0, c0);
        d1 = _mm_xor_si128(d1, c1);
        d2 = _mm_xor_si128(d2, c2);
        d3 = _mm_xor_si128(d3, c3);
        
        _mm_storeu_si128((__m128i *)(out + (i + 0) * AES_BLOCK_SIZE), d0);
        _mm_storeu_si128((__m128i *)(out + (i + 1) * AES_BLOCK_SIZE), d1);
        _mm_storeu_si128((__m128i *)(out + (i + 2) * AES_BLOCK_SIZE), d2);
        _mm_storeu_si128((__m128i *)(out + (i + 3) * AES_BLOCK_SIZE), d3);
        
        i += 4;
    }
    
    // Handle remaining blocks (1-3)
    while (i < blocks) {
        __m128i keystream = _mm_xor_si128(ctr, rk[0]);
        for (int j = 1; j < 14; ++j)
            keystream = _mm_aesenc_si128(keystream, rk[j]);
        keystream = _mm_aesenclast_si128(keystream, rk[14]);
        
        __m128i data = _mm_loadu_si128((__m128i *)(in + i * AES_BLOCK_SIZE));
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)(out + i * AES_BLOCK_SIZE), data);
        
        ctr = increment_counter(ctr);
        i++;
    }
}

// Benchmark helper
static double now_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_256_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) iv[i] = i * 2;

    uint8_t *in, *out;
    posix_memalign((void **)&in, 16, SIZE);
    posix_memalign((void **)&out, 16, SIZE);

    memset(in, 0xAA, SIZE);
    memset(out, 0x00, SIZE);

    __m128i round_keys[15];
    aes256_key_expansion(key, round_keys);

    // Warmup
    aes256_ctr_encrypt(in, out, SIZE, round_keys, iv);

    double start = now_sec();
    for (int iter = 0; iter < 100; iter++) {
        aes256_ctr_encrypt(in, out, SIZE, round_keys, iv);
    }
    double end = now_sec();

    printf("AES-256-CTR AES-NI: %.2f MB/s\n", 
           100 * SIZE / (1024.0 * 1024.0 * (end - start)));

    // Validation print
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", out[i]);
    printf("\n");

    free(in);
    free(out);
    return 0;
}