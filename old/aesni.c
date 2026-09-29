#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include <time.h>

// -------------- Key Expansion (AES-256) --------------
static void aes256_key_expansion(const uint8_t *key, __m128i *round_keys)
{
    __m128i temp1, temp2, temp3;
    temp1 = _mm_loadu_si128((__m128i*)key);
    temp3 = _mm_loadu_si128((__m128i*)(key + 16));
    round_keys[0] = temp1;
    round_keys[1] = temp3;

    #define AES_256_KEY_EXP(K1, K2, I) do { \
        temp2 = _mm_aeskeygenassist_si128(K2, I); \
        temp2 = _mm_shuffle_epi32(temp2, 0xff); \
        K1 = _mm_xor_si128(K1, _mm_slli_si128(K1, 4)); \
        K1 = _mm_xor_si128(K1, _mm_slli_si128(K1, 4)); \
        K1 = _mm_xor_si128(K1, _mm_slli_si128(K1, 4)); \
        K1 = _mm_xor_si128(K1, temp2); \
        round_keys[(I*2)] = K1; \
        temp2 = _mm_aeskeygenassist_si128(K1, 0x00); \
        temp2 = _mm_shuffle_epi32(temp2, 0xaa); \
        K2 = _mm_xor_si128(K2, _mm_slli_si128(K2, 4)); \
        K2 = _mm_xor_si128(K2, _mm_slli_si128(K2, 4)); \
        K2 = _mm_xor_si128(K2, _mm_slli_si128(K2, 4)); \
        K2 = _mm_xor_si128(K2, temp2); \
        round_keys[(I*2)+1] = K2; \
    } while(0)

    AES_256_KEY_EXP(temp1, temp3, 1);
    AES_256_KEY_EXP(temp1, temp3, 2);
    AES_256_KEY_EXP(temp1, temp3, 3);
    AES_256_KEY_EXP(temp1, temp3, 4);
    AES_256_KEY_EXP(temp1, temp3, 5);
    AES_256_KEY_EXP(temp1, temp3, 6);
    AES_256_KEY_EXP(temp1, temp3, 7);
}

// -------------- AES-256 Single Block Encrypt --------------
static inline __m128i aes256_encrypt_block(__m128i in, const __m128i *round_keys)
{
    in = _mm_xor_si128(in, round_keys[0]);
    for (int i = 1; i < 13; i++)
        in = _mm_aesenc_si128(in, round_keys[i]);
    in = _mm_aesenclast_si128(in, round_keys[14]);
    return in;
}

// -------------- CTR Mode Encryption --------------
void aes256_ctr_encrypt(uint8_t *dst, const uint8_t *src, size_t len,
                        const uint8_t key[32], const uint8_t iv[16])
{
    __m128i round_keys[15];
    aes256_key_expansion(key, round_keys);

    __m128i ctr = _mm_loadu_si128((__m128i*)iv);

    for (size_t i = 0; i < len; i += 16)
    {
        __m128i keystream = aes256_encrypt_block(ctr, round_keys);

        __m128i block = _mm_loadu_si128((__m128i*)(src + i));
        block = _mm_xor_si128(block, keystream);
        _mm_storeu_si128((__m128i*)(dst + i), block);

        // increment counter (little endian)
        uint8_t *p = (uint8_t*)&ctr;
        for (int j = 15; j >= 0; j--)
            if (++p[j]) break;
    }
}

// -------------- Simple Benchmark --------------
int main(void)
{
    uint8_t key[32] = {0};
    uint8_t iv[16]  = {0};
    const size_t SIZE = 64 * 1024 * 1024; // 64 MB
    uint8_t *in  = aligned_alloc(16, SIZE);
    uint8_t *out = aligned_alloc(16, SIZE);

    memset(in, 0xAA, SIZE);

    clock_t start = clock();
    aes256_ctr_encrypt(out, in, SIZE, key, iv);
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double mbps = (SIZE / (1024.0*1024.0)) / seconds;
    printf("Encrypted %.1f MB in %.3f s = %.1f MB/s\n",
           SIZE / 1024.0 / 1024.0, seconds, mbps);

    free(in); free(out);
    return 0;
}
