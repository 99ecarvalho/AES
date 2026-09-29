#include "aes_inline_asm.h"

// This demonstrates how to integrate the inline assembly functions 
// into your own C program

//gcc -O3 -march=silvermont -mtune=silvermont -maes -fomit-frame-pointer -funroll-loops -o test_inline_asm test_inline_asm.c -lrt -static

int main(void) {
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

int old_main(void) {
    printf("Testing AES-256-CTR with inline assembly optimization for Atom E3845\n");
    printf("=================================================================\n\n");
    
    // You can call the benchmark function
    int result = run_aes_benchmark();
    
    if (result != 0) {
        printf("Error: Memory allocation failed\n");
        return 1;
    }
    
    printf("\nIntegration example:\n");
    printf("1. Include aes_inline_asm.h in your project\n");
    printf("2. Use aes256_key_expansion_asm() to expand your key\n");
    printf("3. Use aes256_ctr_encrypt_asm() to encrypt your data\n");
    printf("4. For single blocks, use aes256_encrypt_block_asm()\n");
    
    return 0;
}