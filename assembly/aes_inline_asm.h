#ifndef AES_INLINE_ASM_H
#define AES_INLINE_ASM_H

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32

// AES-256 Key expansion using inline assembly
static inline void aes256_key_expansion_asm(const uint8_t *key, __m128i *round_keys) {
    __asm__ volatile (
        // Load initial key parts
        "movdqu (%[key]), %%xmm0\n\t"          // tmp1 = key[0:15]
        "movdqu 16(%[key]), %%xmm2\n\t"        // tmp3 = key[16:31]
        "movdqa %%xmm0, (%[rk])\n\t"           // round_keys[0] = tmp1
        "movdqa %%xmm2, 16(%[rk])\n\t"         // round_keys[1] = tmp3
        
        // Round 1: rcon = 1
        "aeskeygenassist $1, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 32(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 48(%[rk])\n\t"
        
        // Round 2: rcon = 2
        "aeskeygenassist $2, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 64(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 80(%[rk])\n\t"
        
        // Round 3: rcon = 4
        "aeskeygenassist $4, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 96(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 112(%[rk])\n\t"
        
        // Round 4: rcon = 8
        "aeskeygenassist $8, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 128(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 144(%[rk])\n\t"
        
        // Round 5: rcon = 16
        "aeskeygenassist $16, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 160(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 176(%[rk])\n\t"
        
        // Round 6: rcon = 32
        "aeskeygenassist $32, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 192(%[rk])\n\t"
        
        "aeskeygenassist $0, %%xmm0, %%xmm1\n\t"
        "pshufd $0xaa, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm2\n\t"
        "pxor %%xmm1, %%xmm2\n\t"
        "movdqa %%xmm2, 208(%[rk])\n\t"
        
        // Round 7: rcon = 64
        "aeskeygenassist $64, %%xmm2, %%xmm1\n\t"
        "pshufd $0xff, %%xmm1, %%xmm1\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pslldq $4, %%xmm3\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, 224(%[rk])\n\t"
        :
        : [key] "r" (key), [rk] "r" (round_keys)
        : "xmm0", "xmm1", "xmm2", "xmm3", "memory"
    );
}

// Single block AES-256 encryption (unrolled)
static inline __m128i aes256_encrypt_block_asm(__m128i block, const __m128i *rk) {
    __m128i result = block;
    __asm__ volatile (
        "pxor (%[rk]), %[result]\n\t"          // Initial round
        "aesenc 16(%[rk]), %[result]\n\t"      // Round 1
        "aesenc 32(%[rk]), %[result]\n\t"      // Round 2
        "aesenc 48(%[rk]), %[result]\n\t"      // Round 3
        "aesenc 64(%[rk]), %[result]\n\t"      // Round 4
        "aesenc 80(%[rk]), %[result]\n\t"      // Round 5
        "aesenc 96(%[rk]), %[result]\n\t"      // Round 6
        "aesenc 112(%[rk]), %[result]\n\t"     // Round 7
        "aesenc 128(%[rk]), %[result]\n\t"     // Round 8
        "aesenc 144(%[rk]), %[result]\n\t"     // Round 9
        "aesenc 160(%[rk]), %[result]\n\t"     // Round 10
        "aesenc 176(%[rk]), %[result]\n\t"     // Round 11
        "aesenc 192(%[rk]), %[result]\n\t"     // Round 12
        "aesenc 208(%[rk]), %[result]\n\t"     // Round 13
        "aesenclast 224(%[rk]), %[result]\n\t" // Final round
        : [result] "+x" (result)
        : [rk] "r" (rk)
        : "memory"
    );
    return result;
}

// Two-block AES-256 encryption (unrolled, interleaved for Atom)
static inline void aes256_encrypt_2blocks_asm(__m128i *b0, __m128i *b1, const __m128i *rk) {
    __asm__ volatile (
        // Initial round
        "pxor (%[rk]), %[block0]\n\t"
        "pxor (%[rk]), %[block1]\n\t"
        
        // Rounds 1-13 (interleaved to hide latency on Atom)
        "aesenc 16(%[rk]), %[block0]\n\t"
        "aesenc 16(%[rk]), %[block1]\n\t"
        "aesenc 32(%[rk]), %[block0]\n\t"
        "aesenc 32(%[rk]), %[block1]\n\t"
        "aesenc 48(%[rk]), %[block0]\n\t"
        "aesenc 48(%[rk]), %[block1]\n\t"
        "aesenc 64(%[rk]), %[block0]\n\t"
        "aesenc 64(%[rk]), %[block1]\n\t"
        "aesenc 80(%[rk]), %[block0]\n\t"
        "aesenc 80(%[rk]), %[block1]\n\t"
        "aesenc 96(%[rk]), %[block0]\n\t"
        "aesenc 96(%[rk]), %[block1]\n\t"
        "aesenc 112(%[rk]), %[block0]\n\t"
        "aesenc 112(%[rk]), %[block1]\n\t"
        "aesenc 128(%[rk]), %[block0]\n\t"
        "aesenc 128(%[rk]), %[block1]\n\t"
        "aesenc 144(%[rk]), %[block0]\n\t"
        "aesenc 144(%[rk]), %[block1]\n\t"
        "aesenc 160(%[rk]), %[block0]\n\t"
        "aesenc 160(%[rk]), %[block1]\n\t"
        "aesenc 176(%[rk]), %[block0]\n\t"
        "aesenc 176(%[rk]), %[block1]\n\t"
        "aesenc 192(%[rk]), %[block0]\n\t"
        "aesenc 192(%[rk]), %[block1]\n\t"
        "aesenc 208(%[rk]), %[block0]\n\t"
        "aesenc 208(%[rk]), %[block1]\n\t"
        
        // Final round
        "aesenclast 224(%[rk]), %[block0]\n\t"
        "aesenclast 224(%[rk]), %[block1]\n\t"
        
        : [block0] "+x" (*b0), [block1] "+x" (*b1)
        : [rk] "r" (rk)
        : "memory"
    );
}

// AES-256-CTR encryption optimized for Atom E3845 using inline assembly
static void aes256_ctr_encrypt_asm(
    const uint8_t *in, uint8_t *out, size_t len,
    const __m128i *rk, uint8_t *iv)
{
    // Load counter once
    uint64_t ctr_low, ctr_high;
    memcpy(&ctr_low, iv + 8, 8);
    memcpy(&ctr_high, iv, 8);
    
    const uint8_t *in_ptr = in;
    uint8_t *out_ptr = out;
    size_t blocks = len / AES_BLOCK_SIZE;
    
    // Process 2 blocks at a time - optimal for Atom
    while (blocks >= 2) {
        __m128i c0, c1, d0, d1;
        
        // Build counters and encrypt using inline assembly
        __asm__ volatile (
            // Build counters
            "movq %[ctr_high], %%xmm0\n\t"
            "pinsrq $1, %[ctr_low], %%xmm0\n\t"    // c0 = counter 0
            "movdqa %%xmm0, %[counter0]\n\t"
            
            "addq $1, %[ctr_low]\n\t"
            "adcq $0, %[ctr_high]\n\t"
            
            "movq %[ctr_high], %%xmm1\n\t"
            "pinsrq $1, %[ctr_low], %%xmm1\n\t"    // c1 = counter 1
            "movdqa %%xmm1, %[counter1]\n\t"
            
            "addq $1, %[ctr_low]\n\t"
            "adcq $0, %[ctr_high]\n\t"
            
            // Encrypt both counters (2-way interleaved)
            "movdqa %[counter0], %%xmm0\n\t"
            "movdqa %[counter1], %%xmm1\n\t"
            
            "pxor (%[rk]), %%xmm0\n\t"
            "pxor (%[rk]), %%xmm1\n\t"
            "aesenc 16(%[rk]), %%xmm0\n\t"
            "aesenc 16(%[rk]), %%xmm1\n\t"
            "aesenc 32(%[rk]), %%xmm0\n\t"
            "aesenc 32(%[rk]), %%xmm1\n\t"
            "aesenc 48(%[rk]), %%xmm0\n\t"
            "aesenc 48(%[rk]), %%xmm1\n\t"
            "aesenc 64(%[rk]), %%xmm0\n\t"
            "aesenc 64(%[rk]), %%xmm1\n\t"
            "aesenc 80(%[rk]), %%xmm0\n\t"
            "aesenc 80(%[rk]), %%xmm1\n\t"
            "aesenc 96(%[rk]), %%xmm0\n\t"
            "aesenc 96(%[rk]), %%xmm1\n\t"
            "aesenc 112(%[rk]), %%xmm0\n\t"
            "aesenc 112(%[rk]), %%xmm1\n\t"
            "aesenc 128(%[rk]), %%xmm0\n\t"
            "aesenc 128(%[rk]), %%xmm1\n\t"
            "aesenc 144(%[rk]), %%xmm0\n\t"
            "aesenc 144(%[rk]), %%xmm1\n\t"
            "aesenc 160(%[rk]), %%xmm0\n\t"
            "aesenc 160(%[rk]), %%xmm1\n\t"
            "aesenc 176(%[rk]), %%xmm0\n\t"
            "aesenc 176(%[rk]), %%xmm1\n\t"
            "aesenc 192(%[rk]), %%xmm0\n\t"
            "aesenc 192(%[rk]), %%xmm1\n\t"
            "aesenc 208(%[rk]), %%xmm0\n\t"
            "aesenc 208(%[rk]), %%xmm1\n\t"
            "aesenclast 224(%[rk]), %%xmm0\n\t"
            "aesenclast 224(%[rk]), %%xmm1\n\t"
            
            // Load input data and XOR with keystream
            "movdqu (%[input]), %%xmm2\n\t"
            "movdqu 16(%[input]), %%xmm3\n\t"
            "pxor %%xmm0, %%xmm2\n\t"
            "pxor %%xmm1, %%xmm3\n\t"
            
            // Store output
            "movdqu %%xmm2, (%[output])\n\t"
            "movdqu %%xmm3, 16(%[output])\n\t"
            
            : [counter0] "=m" (c0), [counter1] "=m" (c1),
              [ctr_low] "+r" (ctr_low), [ctr_high] "+r" (ctr_high)
            : [rk] "r" (rk), [input] "r" (in_ptr), [output] "r" (out_ptr)
            : "xmm0", "xmm1", "xmm2", "xmm3", "memory"
        );
        
        in_ptr += 2 * AES_BLOCK_SIZE;
        out_ptr += 2 * AES_BLOCK_SIZE;
        blocks -= 2;
    }
    
    // Handle remaining block
    if (blocks > 0) {
        __m128i ctr = _mm_set_epi64x(ctr_low, ctr_high);
        __m128i keystream = aes256_encrypt_block_asm(ctr, rk);
        __m128i data = _mm_loadu_si128((__m128i *)in_ptr);
        data = _mm_xor_si128(data, keystream);
        _mm_storeu_si128((__m128i *)out_ptr, data);
    }
}

// Benchmark helper
static double now_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// Example usage function that can be integrated into other C programs
int run_aes_benchmark(void) {
    const size_t SIZE = 4 * (1024 * 1024); // 4 MB for benchmark
    
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_256_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) iv[i] = i * 2;

    uint8_t *in, *out;
    if (posix_memalign((void **)&in, 16, SIZE) != 0) return -1;
    if (posix_memalign((void **)&out, 16, SIZE) != 0) {
        free(in);
        return -1;
    }

    memset(in, 0xAA, SIZE);
    memset(out, 0x00, SIZE);

    __m128i round_keys[15];
    aes256_key_expansion_asm(key, round_keys);

    // Warmup
    aes256_ctr_encrypt_asm(in, out, SIZE, round_keys, iv);

    double start = now_sec();
    for (int iter = 0; iter < 100; iter++) {
        aes256_ctr_encrypt_asm(in, out, SIZE, round_keys, iv);
    }
    double end = now_sec();

    double throughput = 100 * SIZE / (1024.0 * 1024.0 * (end - start));
    printf("AES-256-CTR AES-NI (Atom optimized inline asm): %.2f MB/s\n", throughput);

    // Validation print
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", out[i]);
    printf("\n");

    free(in);
    free(out);
    return 0;
}

// Main function for standalone testing
#ifdef STANDALONE_TEST
int main(void) {
    return run_aes_benchmark();
}
#endif

#endif // AES_INLINE_ASM_H