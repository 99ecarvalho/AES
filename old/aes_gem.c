//gcc -O3 -march=native -mtune=silvermont -maes -Wall -std=c99 -o aes_gem aes_gem.c -lrt -static
#define _POSIX_C_SOURCE 200809L
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32
#define SIZE (1024 * 1024 * 100) // Increased size for better measurement

// Key Expansion (Kept the same)
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

// Encrypt a single block with AES-256 (Manually Unrolled)
static inline __m128i aes256_encrypt_block(__m128i block, const __m128i *round_keys) {
    block = _mm_xor_si128(block, round_keys[0]);
    block = _mm_aesenc_si128(block, round_keys[1]);
    block = _mm_aesenc_si128(block, round_keys[2]);
    block = _mm_aesenc_si128(block, round_keys[3]);
    block = _mm_aesenc_si128(block, round_keys[4]);
    block = _mm_aesenc_si128(block, round_keys[5]);
    block = _mm_aesenc_si128(block, round_keys[6]);
    block = _mm_aesenc_si128(block, round_keys[7]);
    block = _mm_aesenc_si128(block, round_keys[8]);
    block = _mm_aesenc_si128(block, round_keys[9]);
    block = _mm_aesenc_si128(block, round_keys[10]);
    block = _mm_aesenc_si128(block, round_keys[11]);
    block = _mm_aesenc_si128(block, round_keys[12]);
    block = _mm_aesenc_si128(block, round_keys[13]);
    block = _mm_aesenclast_si128(block, round_keys[14]);
    return block;
}

// Optimized CTR mode with 16-way unrolling and aligned access
static void aes256_ctr_encrypt_optimized(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *round_keys, uint8_t *iv)
{
    // The counter increment '1' in little-endian format: [0 | 1]
    const __m128i one = _mm_set_epi64x(0, 1);
    
    // Load initial counter state
    __m128i c[16]; // 16 independent counter variables
    c[0] = _mm_loadu_si128((__m128i *)iv);
    
    // Generate the next 15 counters incrementally
    for (int i = 1; i < 16; ++i) {
        c[i] = _mm_add_epi64(c[i-1], one);
    }

    // Number of 16-block (256-byte) chunks
    size_t sixteen_block_chunks = len / (AES_BLOCK_SIZE * 16); 
    size_t offset = 0;

    // Increment vector for the next chunk: 16 (for c[0])
    const __m128i sixteen = _mm_set_epi64x(0, 16);

    for (size_t i = 0; i < sixteen_block_chunks; ++i) {
        // 1. Encrypt 16 counters in parallel (Pipelining)
        __m128i k[16];
        for (int j = 0; j < 16; ++j) {
            k[j] = aes256_encrypt_block(c[j], round_keys);
        }
        
        // 2. Load data, XOR with keystream, and Store (Aligned I/O)
        for (int j = 0; j < 16; ++j) {
            // Note: Using _mm_load_si128 and _mm_store_si128 for aligned access
            __m128i data = _mm_load_si128((__m128i *)(in + offset + AES_BLOCK_SIZE * j));
            data = _mm_xor_si128(data, k[j]);
            _mm_store_si128((__m128i *)(out + offset + AES_BLOCK_SIZE * j), data);
        }

        // 3. Update offset and increment all 16 counters by 16 for the next iteration
        offset += AES_BLOCK_SIZE * 16; 
        for (int j = 0; j < 16; ++j) {
            c[j] = _mm_add_epi64(c[j], sixteen);
        }
    }
    
    // Handle the remaining blocks (Remainder Loop)
    size_t remainder_blocks = (len / AES_BLOCK_SIZE) % 16;
    for (size_t j = 0; j < remainder_blocks; ++j) {
        __m128i keystream = aes256_encrypt_block(c[0], round_keys);
        // Use unaligned for remainder, as alignment is not guaranteed for the tail end
        __m128i data = _mm_loadu_si128((__m128i *)(in + offset)); 
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)(out + offset), data);

        // Increment counter by 1
        c[0] = _mm_add_epi64(c[0], one);
        offset += AES_BLOCK_SIZE;
    }
}

// Benchmark helper (Kept the same)
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
    // CRITICAL: Ensure 16-byte alignment using posix_memalign
    if (posix_memalign((void **)&in, 16, SIZE) != 0 || 
        posix_memalign((void **)&out, 16, SIZE) != 0) {
        perror("posix_memalign failed");
        return 1;
    }

    memset(in, 0xAA, SIZE);
    memset(out, 0x00, SIZE);

    __m128i round_keys[15];
    aes256_key_expansion(key, round_keys);

    double start = now_sec();
    aes256_ctr_encrypt_optimized(in, out, SIZE, round_keys, iv); 
    double end = now_sec();

    printf("AES-256-CTR AES-NI (16-way Unrolled, Aligned): %.2f MB/s\n", 
           SIZE / (1024.0 * 1024.0 * (end - start)));

    // small validation print
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", out[i]);
    printf("\n");

    free(in);
    free(out);
    return 0;
}

/*

Optimization Rationale for Atom E3845The Intel Atom E3845 has a simple, in-order execution pipeline.

This means if one instruction stalls (e.g., waiting for the result of a high-latency instruction),
the entire pipeline stalls. The $\text{AESENC}$ instruction has a dependency on its own previous
result, creating a long dependency chain.16-Way Unrolling (Maximizing ILP):
By managing 16 separate counter streams (c[0] through c[15]), we provide the CPU with 16 completely
independent sequences of $\text{AESENC}$ operations. The in-order core can execute the initial rounds
of one block's encryption while the later rounds of a previous block are completing, significantly
reducing the apparent latency and keeping execution units saturated.This is the single most effective
optimization for CTR mode on low-power, in-order architectures like Bay Trail.Manual $\text{AESENC}$
Unrolling (Minimizing Overhead): Removing the loop structure in aes256_encrypt_block eliminates branches
and loop control instructions inside the hottest part of the code, which is critical for an in-order CPU
where misprediction or branch overhead is costly.Aligned Memory Access: Using _mm_load_si128 and _mm_store_si128
(instead of _mm_loadu_si128 and _mm_storeu_si128) leverages the 16-byte alignment guaranteed by posix_memalign.
On the E3845, this ensures memory access is handled by a single micro-operation and prevents potential
performance penalties associated with unaligned access crossing cache lines.

These combined strategies should provide a substantial performance boost over the original implementation
and give you an excellent benchmark result against other implementations.Let me know if you want to explore
the key expansion optimization, although it's usually negligible since it only runs once.
*/