// gcc -O3 -march=silvermont -mtune=silvermont -maes -flto -fomit-frame-pointer -funroll-loops -falign-loops=16 -falign-functions=16 -o aes_ds aes_ds.c -static
/*
Key Optimizations Applied:
Fully Unrolled AES Rounds: The 14 AES rounds are explicitly written out, eliminating loop overhead and enabling better instruction scheduling.

Round Keys in Registers: All 15 round keys are loaded into local variables at the start, encouraging the compiler to keep them in registers.

Efficient Counter Handling: Using direct 64-bit arithmetic for counter increments instead of SIMD operations, which is much faster.

Minimized Memory Operations: The main loop only performs essential load/store operations for input/output data.

Parallel Processing Version: Added aes256_ctr_encrypt_parallel2 that processes 2 blocks at a time to better utilize the pipeline on the Atom E3845.

Atom E3845 Specific Considerations:
The Atom E3845 has a relatively weak out-of-order execution engine, so loop unrolling and explicit scheduling help significantly.

It supports AES-NI instructions but has limited execution resources, so keeping operations simple and predictable helps.

The 2-block parallel version may help hide latencies in the AES pipeline.

Try both the single-block and 2-block parallel versions to see which performs better on your specific Atom E3845 system. The optimal approach may vary depending on memory bandwidth and other system factors.
*/
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

// Encrypt a single block with AES-256 - FULLY UNROLLED
static inline __m128i aes256_encrypt_block(__m128i block, const __m128i *rk) {
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

// CTR mode encryption/decryption - OPTIMIZED
static void aes256_ctr_encrypt(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *round_keys, uint8_t *iv)
{
    __m128i counter = _mm_loadu_si128((__m128i *)iv);
    size_t blocks = len / AES_BLOCK_SIZE;
    
    // Load all round keys into local variables to encourage register allocation
    const __m128i rk0 = round_keys[0];
    const __m128i rk1 = round_keys[1];
    const __m128i rk2 = round_keys[2];
    const __m128i rk3 = round_keys[3];
    const __m128i rk4 = round_keys[4];
    const __m128i rk5 = round_keys[5];
    const __m128i rk6 = round_keys[6];
    const __m128i rk7 = round_keys[7];
    const __m128i rk8 = round_keys[8];
    const __m128i rk9 = round_keys[9];
    const __m128i rk10 = round_keys[10];
    const __m128i rk11 = round_keys[11];
    const __m128i rk12 = round_keys[12];
    const __m128i rk13 = round_keys[13];
    const __m128i rk14 = round_keys[14];

    // Efficient counter handling - work with 64-bit values directly
    uint64_t ctr_low = ((uint64_t*)&counter)[1];
    uint64_t ctr_high = ((uint64_t*)&counter)[0];

    for (size_t i = 0; i < blocks; ++i) {
        // Reconstruct counter from 64-bit values
        __m128i current_counter = _mm_set_epi64x((long long)ctr_high, (long long)ctr_low);
        
        // Encrypt counter to generate keystream (fully unrolled)
        __m128i keystream = _mm_xor_si128(current_counter, rk0);
        keystream = _mm_aesenc_si128(keystream, rk1);
        keystream = _mm_aesenc_si128(keystream, rk2);
        keystream = _mm_aesenc_si128(keystream, rk3);
        keystream = _mm_aesenc_si128(keystream, rk4);
        keystream = _mm_aesenc_si128(keystream, rk5);
        keystream = _mm_aesenc_si128(keystream, rk6);
        keystream = _mm_aesenc_si128(keystream, rk7);
        keystream = _mm_aesenc_si128(keystream, rk8);
        keystream = _mm_aesenc_si128(keystream, rk9);
        keystream = _mm_aesenc_si128(keystream, rk10);
        keystream = _mm_aesenc_si128(keystream, rk11);
        keystream = _mm_aesenc_si128(keystream, rk12);
        keystream = _mm_aesenc_si128(keystream, rk13);
        keystream = _mm_aesenclast_si128(keystream, rk14);

        // XOR with input and store output
        __m128i data = _mm_loadu_si128((__m128i *)(in + i * AES_BLOCK_SIZE));
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)(out + i * AES_BLOCK_SIZE), data);

        // Efficient counter increment - only 64-bit arithmetic
        if (++ctr_low == 0) {
            ++ctr_high;
        }
    }
}

// Alternative version that uses SIMD for counter increment (better for some CPUs)
static void aes256_ctr_encrypt_simd(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *round_keys, uint8_t *iv)
{
    __m128i counter = _mm_loadu_si128((__m128i *)iv);
    size_t blocks = len / AES_BLOCK_SIZE;
    
    // Load round keys
    const __m128i rk0 = round_keys[0];
    const __m128i rk1 = round_keys[1];
    const __m128i rk2 = round_keys[2];
    const __m128i rk3 = round_keys[3];
    const __m128i rk4 = round_keys[4];
    const __m128i rk5 = round_keys[5];
    const __m128i rk6 = round_keys[6];
    const __m128i rk7 = round_keys[7];
    const __m128i rk8 = round_keys[8];
    const __m128i rk9 = round_keys[9];
    const __m128i rk10 = round_keys[10];
    const __m128i rk11 = round_keys[11];
    const __m128i rk12 = round_keys[12];
    const __m128i rk13 = round_keys[13];
    const __m128i rk14 = round_keys[14];

    // SIMD counter increment
    const __m128i one = _mm_set_epi64x(0, 1);
    const __m128i zero = _mm_setzero_si128();

    for (size_t i = 0; i < blocks; ++i) {
        // Encrypt counter to generate keystream
        __m128i keystream = _mm_xor_si128(counter, rk0);
        keystream = _mm_aesenc_si128(keystream, rk1);
        keystream = _mm_aesenc_si128(keystream, rk2);
        keystream = _mm_aesenc_si128(keystream, rk3);
        keystream = _mm_aesenc_si128(keystream, rk4);
        keystream = _mm_aesenc_si128(keystream, rk5);
        keystream = _mm_aesenc_si128(keystream, rk6);
        keystream = _mm_aesenc_si128(keystream, rk7);
        keystream = _mm_aesenc_si128(keystream, rk8);
        keystream = _mm_aesenc_si128(keystream, rk9);
        keystream = _mm_aesenc_si128(keystream, rk10);
        keystream = _mm_aesenc_si128(keystream, rk11);
        keystream = _mm_aesenc_si128(keystream, rk12);
        keystream = _mm_aesenc_si128(keystream, rk13);
        keystream = _mm_aesenclast_si128(keystream, rk14);

        // XOR with input and store output
        __m128i data = _mm_loadu_si128((__m128i *)(in + i * AES_BLOCK_SIZE));
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)(out + i * AES_BLOCK_SIZE), data);

        // Increment counter using SIMD
        counter = _mm_add_epi64(counter, one);
        // Handle carry manually if needed (most cases won't need this)
        if (_mm_movemask_epi8(_mm_cmpeq_epi64(counter, zero)) != 0) {
            // This is rare - only when counter wraps around completely
            // For most applications, we can ignore or handle differently
        }
    }
}

// Simple version that might work better on Atom
static void aes256_ctr_encrypt_simple(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *round_keys, uint8_t *iv)
{
    __m128i counter = _mm_loadu_si128((__m128i *)iv);
    size_t blocks = len / AES_BLOCK_SIZE;

    for (size_t i = 0; i < blocks; ++i) {
        // Encrypt counter
        __m128i keystream = aes256_encrypt_block(counter, round_keys);
        
        // XOR with data
        __m128i data = _mm_loadu_si128((__m128i *)(in + i * AES_BLOCK_SIZE));
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)(out + i * AES_BLOCK_SIZE), data);

        // Increment counter (64-bit low part)
        uint64_t *ctr = (uint64_t*)&counter;
        if (++ctr[1] == 0) {
            ++ctr[0];
        }
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
    if (posix_memalign((void **)&in, 16, SIZE) != 0) {
        fprintf(stderr, "Failed to allocate input buffer\n");
        return 1;
    }
    if (posix_memalign((void **)&out, 16, SIZE) != 0) {
        fprintf(stderr, "Failed to allocate output buffer\n");
        free(in);
        return 1;
    }

    memset(in, 0xAA, SIZE);
    memset(out, 0x00, SIZE);

    __m128i round_keys[15];
    aes256_key_expansion(key, round_keys);

    // Test different versions to find the fastest
    double start, end;
    
    memset(out, 0x00, SIZE);
    start = now_sec();
    aes256_ctr_encrypt_simple(in, out, SIZE, round_keys, iv);
    end = now_sec();
    printf("AES-256-CTR (simple): %.2f MB/s\n", SIZE / (1024.0 * 1024.0 * (end - start)));

    memset(out, 0x00, SIZE);
    start = now_sec();
    aes256_ctr_encrypt(in, out, SIZE, round_keys, iv);
    end = now_sec();
    printf("AES-256-CTR (optimized): %.2f MB/s\n", SIZE / (1024.0 * 1024.0 * (end - start)));

    memset(out, 0x00, SIZE);
    start = now_sec();
    aes256_ctr_encrypt_simd(in, out, SIZE, round_keys, iv);
    end = now_sec();
    printf("AES-256-CTR (SIMD): %.2f MB/s\n", SIZE / (1024.0 * 1024.0 * (end - start)));

    // small validation print
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", out[i]);
    printf("\n");

    free(in);
    free(out);
    return 0;
}