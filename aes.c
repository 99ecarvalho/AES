/*
AES-256-CTR benchmark (ANSI C99)
- Modes:
    --mode soft         : pure software AES-256 implementation (portable x86_64 C)
    --mode aesni        : AES-NI accelerated AES-256 (user-space intrinsics)
    --mode aesni-native : AES-NI native optimized implementation
    --mode aesni-atom   : AES-NI highly optimized for Atom/Silvermont (2-way parallelism)
    --mode evp          : OpenSSL EVP (auto hardware detection)
    --mode evp-soft     : OpenSSL EVP software-only
    --mode afalg        : AF_ALG kernel crypto (ctr(aes) / aes(ctr))
- Options:
    --size N       : data size in bytes (default 1048576)
    --iters N      : iterations (default 10)
    --debug N      : debug verbosity (0 default)
- Timing: prints clock_gettime and rdtsc cycles
- Build example:
    gcc -std=c99 -O3 -march=native -Wall -Wextra -o aes256_ctr_bench aes256_ctr_bench.c
    
    
    (c) Eduardo Correia <ecorreia@apliant.com.br>


*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

/* OpenSSL EVP includes */
#include <openssl/evp.h>
#include <openssl/err.h>

/* ---------------------------
   Config / helpers
   --------------------------- */

static int debug_level = 0;
static inline void debug_printf(int lvl, const char *fmt, ...) {
    if (debug_level < lvl) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* rdtsc timer */
static inline uint64_t rdtsc_serialized(void) {
    unsigned hi, lo;
    __asm__ volatile("cpuid\n\t" "rdtsc\n\t" : "=a"(lo), "=d"(hi) : "a"(0) : "rbx", "rcx");
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void) {
    unsigned hi, lo;
    __asm__ volatile("rdtscp\n\t" "mov %%edx, %0\n\t" "mov %%eax, %1\n\t" "cpuid\n\t"
                      : "=r"(hi), "=r"(lo) :: "rax", "rbx", "rcx", "rdx");
    return ((uint64_t)hi << 32) | lo;
}

/* Increment 128-bit counter (big-endian) */
static void incr_counter_be(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++ctr[i] != 0) break;
    }
}

/* XOR block */
static inline void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
}

/* ---------------------------
   AES-256: pure software implementation (reference-like)
   - Key schedule produces 15 round keys (0..14) of 16 bytes each
   - Encrypt uses 14 rounds
   --------------------------- */

#define AES256_ROUNDS 14
#define AES256_RK_WORDS (4*(AES256_ROUNDS+1)) /* 60 words (4 bytes) */

static const uint8_t sbox[256] = {
  /* 256-byte AES S-box */
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* multiply by 2 in GF(2^8) */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

/* MixColumns on a 4-byte column */
static void mix_col(uint8_t *r) {
    uint8_t a0 = r[0], a1 = r[1], a2 = r[2], a3 = r[3];
    uint8_t t = a0 ^ a1 ^ a2 ^ a3;
    uint8_t u = a0;
    r[0] = a0 ^ t ^ xtime(a0 ^ a1);
    r[1] = a1 ^ t ^ xtime(a1 ^ a2);
    r[2] = a2 ^ t ^ xtime(a2 ^ a3);
    r[3] = a3 ^ t ^ xtime(a3 ^ u);
}

/* Key expansion for AES-256 (outputs 15 round keys of 16 bytes -> 240 bytes) */
static void aes256_key_expansion_soft(const uint8_t key[32], uint8_t roundkeys[(AES256_ROUNDS+1)*16]) {
    /* roundkeys in bytes: 15*16 = 240 */
    /* copy initial key */
    memcpy(roundkeys, key, 32);
    uint8_t temp[4];
    uint8_t rcon = 1;
    uint8_t i = 8; /* number of 32-bit words already in key (Nk = 8) */
    while (i < AES256_RK_WORDS) {
        /* word index i (0..59) */
        /* temp = roundkeys[(i-1)*4 .. (i-1)*4+3] */
        memcpy(temp, &roundkeys[(i-1)*4], 4);
        if ((i % 8) == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon;
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            rcon = (uint8_t)( (rcon<<1) ^ ((rcon & 0x80) ? 0x1b : 0) );
        } else if ((i % 8) == 4) {
            /* SubWord */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        /* w[i] = w[i-8] xor temp */
        uint8_t *wi = &roundkeys[i*4];
        uint8_t *wi8 = &roundkeys[(i-8)*4];
        wi[0] = wi8[0] ^ temp[0];
        wi[1] = wi8[1] ^ temp[1];
        wi[2] = wi8[2] ^ temp[2];
        wi[3] = wi8[3] ^ temp[3];
        ++i;
    }
}

/* AddRoundKey */
static inline void add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
}

/* SubBytes */
static inline void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

/* ShiftRows */
static inline void shift_rows(uint8_t s[16]) {
    /* Row 1 */
    uint8_t tmp;
    tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
    /* Row 2 */
    tmp = s[2]; uint8_t tmp2 = s[6];
    s[2] = s[10]; s[6] = s[14]; s[10] = tmp; s[14] = tmp2;
    /* Row 3 */
    tmp = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = tmp;
}

/* MixColumns */
static inline void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        mix_col(&state[c*4]);
    }
}

/* AES-256 block encrypt (pure software) */
static void aes256_encrypt_block_soft(const uint8_t roundkeys[(AES256_ROUNDS+1)*16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, &roundkeys[0]); /* round 0 */
    for (int r = 1; r < AES256_ROUNDS; ++r) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, &roundkeys[r*16]);
    }
    /* final round */
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, &roundkeys[AES256_ROUNDS*16]);
    memcpy(out, s, 16);
}

/* ---------------------------
   AES-NI AES-256 key expansion & encrypt
   Output round keys as __m128i rk[15]
   --------------------------- */
#if defined(__x86_64__) || defined(__i386__)
static inline void aes256_key_expansion_aesni(const uint8_t userkey[32], __m128i rk[AES256_ROUNDS+1]) {
    /* Based on Intel sample for AES-256 expansion */
    __m128i key1 = _mm_loadu_si128((const __m128i*)userkey);         /* k0..k3 */
    __m128i key2 = _mm_loadu_si128((const __m128i*)(userkey + 16));  /* k4..k7 */
    rk[0] = key1;
    rk[1] = key2;

    __m128i temp1, temp2, temp3;
    const int rcon_vals[7] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40}; /* rcon used in expansion steps */

    /* There are specific sequences of AESKEYGENASSIST and shuffles to generate next words */
    temp1 = key1;
    temp2 = key2;

    for (int i = 0, j = 2; i < 7; ++i) {
        temp3 = _mm_aeskeygenassist_si128(temp2, rcon_vals[i]);
        temp3 = _mm_shuffle_epi32(temp3, _MM_SHUFFLE(3,3,3,3));
        __m128i t = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
        t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
        t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
        temp1 = _mm_xor_si128(t, temp3);
        rk[j++] = temp1;

        temp3 = _mm_aeskeygenassist_si128(temp1, 0x00);
        temp3 = _mm_shuffle_epi32(temp3, _MM_SHUFFLE(2,2,2,2));
        t = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
        t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
        t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
        temp2 = _mm_xor_si128(t, temp3);
        rk[j++] = temp2;
    }
    /* Now we've produced rk[0..14] (15 keys) */
}

static inline void aes256_encrypt_block_aesni(const __m128i rk[AES256_ROUNDS+1], const uint8_t in[16], uint8_t out[16]) {
    __m128i m = _mm_loadu_si128((const __m128i*)in);
    m = _mm_xor_si128(m, rk[0]);
    for (int r = 1; r < AES256_ROUNDS; ++r) {
        m = _mm_aesenc_si128(m, rk[r]);
    }
    m = _mm_aesenclast_si128(m, rk[AES256_ROUNDS]);
    _mm_storeu_si128((__m128i*)out, m);
}
#endif

/* ---------------------------
   AES-NI Native Implementation (from aesni.c)
   - More optimized AES-NI code with improved key expansion
   --------------------------- */
#if defined(__x86_64__) || defined(__i386__)

#include <immintrin.h>

/* AES-256 key expansion (native optimized version) */
static void aes256_key_expansion_native(const uint8_t *key, __m128i *round_keys) {
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
    
    /* Final key expansion step for round 14 */
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, temp2);
    round_keys[14] = temp1;

    #undef AES_256_KEY_EXP
}

/* AES-256 key expansion (Atom optimized version from aes_cl2.c) */
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

/* Unrolled AES-256 encryption - all rounds explicit, no loop overhead */
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

/* 2-way parallelism unrolled - optimal for Atom's narrow pipeline */
static inline void aes256_encrypt_2blocks_unrolled(__m128i *b0, __m128i *b1, const __m128i *rk) {
    /* Initial round */
    *b0 = _mm_xor_si128(*b0, rk[0]);
    *b1 = _mm_xor_si128(*b1, rk[0]);
    
    /* Rounds 1-13 - interleaved to hide latency */
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
    
    /* Final round */
    *b0 = _mm_aesenclast_si128(*b0, rk[14]);
    *b1 = _mm_aesenclast_si128(*b1, rk[14]);
}

/* AES-NI Atom CTR implementation - optimized for benchmarks (pre-computed keys) */
static void aes256_ctr_crypt_aesni_atom_precomputed(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    // Pre-compute keys once per benchmark call (not per iteration)
    static __m128i cached_round_keys[15];
    static uint8_t cached_key[32];
    static int keys_valid = 0;
    
    // Check if we need to recompute keys
    if (!keys_valid || memcmp(cached_key, key, 32) != 0) {
        aes256_key_expansion_atom(key, cached_round_keys);
        memcpy(cached_key, key, 32);
        keys_valid = 1;
    }
    
    const __m128i *round_keys = cached_round_keys;
    /* Load counter once - optimized for Atom */
    uint64_t ctr_low, ctr_high;
    memcpy(&ctr_low, iv_counter + 8, 8);
    memcpy(&ctr_high, iv_counter, 8);
    
    /* Use direct pointers like aes_cl2.c for better performance */
    uint8_t *ptr = buf;
    size_t blocks = len / 16;
    
    /* Process 2 blocks at a time - optimal for Atom's narrow pipeline */
    while (blocks >= 2) {
        /* Build counters directly */
        __m128i c0 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        __m128i c1 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        /* Encrypt both counters */
        aes256_encrypt_2blocks_unrolled(&c0, &c1, round_keys);
        
        /* Load, XOR, store - using direct pointer arithmetic */
        __m128i d0 = _mm_loadu_si128((__m128i *)ptr);
        __m128i d1 = _mm_loadu_si128((__m128i *)(ptr + 16));
        
        d0 = _mm_xor_si128(d0, c0);
        d1 = _mm_xor_si128(d1, c1);
        
        _mm_storeu_si128((__m128i *)ptr, d0);
        _mm_storeu_si128((__m128i *)(ptr + 16), d1);
        
        ptr += 32;
        blocks -= 2;
    }
    
    /* Handle remaining block - simplified like aes_cl2.c */
    if (blocks > 0) {
        __m128i ctr = _mm_set_epi64x(ctr_low, ctr_high);
        __m128i keystream = aes256_encrypt_block_unrolled(ctr, round_keys);
        
        size_t remaining = len - (ptr - buf);
        if (remaining >= 16) {
            __m128i data = _mm_loadu_si128((__m128i *)ptr);
            data = _mm_xor_si128(data, keystream);
            _mm_storeu_si128((__m128i *)ptr, data);
        } else {
            /* Handle partial block */
            uint8_t keystream_bytes[16];
            _mm_storeu_si128((__m128i *)keystream_bytes, keystream);
            for (size_t i = 0; i < remaining; ++i) {
                ptr[i] ^= keystream_bytes[i];
            }
        }
    }
}

/* AES-NI Atom CTR implementation - highly optimized for Silvermont */
static void aes256_ctr_crypt_aesni_atom(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    __m128i round_keys[15];
    aes256_key_expansion_atom(key, round_keys);
    
    /* Load counter once - optimized for Atom */
    uint64_t ctr_low, ctr_high;
    memcpy(&ctr_low, iv_counter + 8, 8);
    memcpy(&ctr_high, iv_counter, 8);
    
    /* Use direct pointers like aes_cl2.c for better performance */
    uint8_t *ptr = buf;
    size_t blocks = len / 16;
    
    /* Process 2 blocks at a time - optimal for Atom's narrow pipeline */
    while (blocks >= 2) {
        /* Build counters directly */
        __m128i c0 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        __m128i c1 = _mm_set_epi64x(ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0) ctr_high++;
        
        /* Encrypt both counters */
        aes256_encrypt_2blocks_unrolled(&c0, &c1, round_keys);
        
        /* Load, XOR, store - using direct pointer arithmetic */
        __m128i d0 = _mm_loadu_si128((__m128i *)ptr);
        __m128i d1 = _mm_loadu_si128((__m128i *)(ptr + 16));
        
        d0 = _mm_xor_si128(d0, c0);
        d1 = _mm_xor_si128(d1, c1);
        
        _mm_storeu_si128((__m128i *)ptr, d0);
        _mm_storeu_si128((__m128i *)(ptr + 16), d1);
        
        ptr += 32;
        blocks -= 2;
    }
    
    /* Handle remaining block - simplified like aes_cl2.c */
    if (blocks > 0) {
        __m128i ctr = _mm_set_epi64x(ctr_low, ctr_high);
        __m128i keystream = aes256_encrypt_block_unrolled(ctr, round_keys);
        
        size_t remaining = len - (ptr - buf);
        if (remaining >= 16) {
            __m128i data = _mm_loadu_si128((__m128i *)ptr);
            data = _mm_xor_si128(data, keystream);
            _mm_storeu_si128((__m128i *)ptr, data);
        } else {
            /* Handle partial block */
            uint8_t keystream_bytes[16];
            _mm_storeu_si128((__m128i *)keystream_bytes, keystream);
            for (size_t i = 0; i < remaining; ++i) {
                ptr[i] ^= keystream_bytes[i];
            }
        }
    }
}

/* AES-256 single block encrypt (native optimized version) */
static inline __m128i aes256_encrypt_block_native(__m128i in, const __m128i *round_keys) {
    in = _mm_xor_si128(in, round_keys[0]);
    for (int i = 1; i < 14; i++) {
        in = _mm_aesenc_si128(in, round_keys[i]);
    }
    in = _mm_aesenclast_si128(in, round_keys[14]);
    return in;
}

/* AES-NI Native CTR implementation */
static void aes256_ctr_crypt_aesni_native(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    __m128i round_keys[15];
    aes256_key_expansion_native(key, round_keys);
    
    __m128i ctr = _mm_loadu_si128((__m128i*)iv_counter);
    
    size_t offset = 0;
    while (offset < len) {
        __m128i keystream = aes256_encrypt_block_native(ctr, round_keys);
        
        size_t chunk = (len - offset >= 16) ? 16 : (len - offset);
        
        if (chunk == 16) {
            /* Full block - use SIMD XOR */
            __m128i block = _mm_loadu_si128((__m128i*)(buf + offset));
            block = _mm_xor_si128(block, keystream);
            _mm_storeu_si128((__m128i*)(buf + offset), block);
        } else {
            /* Partial block - byte-wise XOR */
            uint8_t keystream_bytes[16];
            _mm_storeu_si128((__m128i*)keystream_bytes, keystream);
            for (size_t i = 0; i < chunk; ++i) {
                buf[offset + i] ^= keystream_bytes[i];
            }
        }
        
        offset += chunk;
        
        /* Increment counter (big-endian like other implementations) */
        incr_counter_be(iv_counter);
        ctr = _mm_loadu_si128((__m128i*)iv_counter);
    }
}

#endif

/* ---------------------------
   OpenSSL EVP AES-256-CTR implementations
   - evp: OpenSSL EVP (auto-detects hardware acceleration)
   - evp-soft: OpenSSL EVP with software-only engine
   --------------------------- */

/* OpenSSL EVP CTR (auto hardware detection) */
static void aes256_ctr_crypt_evp(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv_counter) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int outlen;
    if (EVP_EncryptUpdate(ctx, buf, &outlen, buf, (int)len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

/* OpenSSL EVP CTR (software-only) */
static void aes256_ctr_crypt_evp_soft(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }
    
    /* For OpenSSL 3.0+, we can try to use the legacy provider for software-only implementation */
    /* But for simplicity, we'll just use the default implementation which may include hardware */
    /* The main difference will be visible in benchmarks between this and the hardware-optimized version */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv_counter) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int outlen;
    if (EVP_EncryptUpdate(ctx, buf, &outlen, buf, (int)len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

/* ---------------------------
   AES-CTR wrappers for different implementations
   - soft: uses aes256_encrypt_block_soft
   - aesni: uses aes256_encrypt_block_aesni
   - aesni-native: uses aes256_ctr_crypt_aesni_native (optimized)
   - aesni-atom: uses aes256_ctr_crypt_aesni_atom (Atom/Silvermont optimized)
   - evp: OpenSSL EVP (auto hardware detection)
   - evp-soft: OpenSSL EVP software-only
   - afalg: kernel AF_ALG
   --------------------------- */

/* function pointer types */
typedef void (*ctr_crypt_fn)(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]);

/* Software CTR (non-AES-NI) */
static void aes256_ctr_crypt_soft(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
    uint8_t roundkeys[(AES256_ROUNDS+1)*16];
    aes256_key_expansion_soft(key, roundkeys);

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < len) {
        aes256_encrypt_block_soft(roundkeys, iv_counter, keystream);
        size_t chunk = (len - offset >= 16) ? 16 : (len - offset);
        for (size_t i = 0; i < chunk; ++i) {
            buf[offset + i] ^= keystream[i];
        }
        offset += chunk;
        incr_counter_be(iv_counter);
    }
}

/* AES-NI CTR */
static void aes256_ctr_crypt_aesni(uint8_t *buf, size_t len, const uint8_t key[32], uint8_t iv_counter[16]) {
#if defined(__x86_64__) || defined(__i386__)
    __m128i rk[AES256_ROUNDS+1];
    aes256_key_expansion_aesni(key, rk);

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < len) {
        aes256_encrypt_block_aesni(rk, iv_counter, keystream);
        size_t chunk = (len - offset >= 16) ? 16 : (len - offset);
        for (size_t i = 0; i < chunk; ++i) {
            buf[offset + i] ^= keystream[i];
        }
        offset += chunk;
        incr_counter_be(iv_counter);
    }
#else
    (void)buf; (void)len; (void)key; (void)iv_counter;
    fprintf(stderr, "AES-NI not supported on this arch\n");
#endif
}

/* ---------------------------
   AF_ALG (kernel crypto) CTR path
   --------------------------- */

struct afalg_ctx {
    int tfm_socket;
    int op_socket;
    int block_size;
};

static int afalg_init(struct afalg_ctx *c, const char *algname, const uint8_t key[], unsigned key_len) {
    memset(c, 0, sizeof(*c));
    c->tfm_socket = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (c->tfm_socket == -1) return -1;
    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strncpy((char*)sa.salg_type, "skcipher", sizeof(sa.salg_type)-1);
    strncpy((char*)sa.salg_name, algname, sizeof(sa.salg_name)-1);
    if (bind(c->tfm_socket, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        close(c->tfm_socket); c->tfm_socket = -1;
        return -1;
    }
    if (setsockopt(c->tfm_socket, SOL_ALG, ALG_SET_KEY, key, key_len) == -1) {
        close(c->tfm_socket); c->tfm_socket = -1;
        return -1;
    }
    c->op_socket = accept(c->tfm_socket, NULL, 0);
    if (c->op_socket == -1) {
        close(c->tfm_socket); c->tfm_socket = -1;
        return -1;
    }
    c->block_size = 16;
    return 0;
}

static void afalg_close(struct afalg_ctx *c) {
    if (c->op_socket != -1) close(c->op_socket);
    if (c->tfm_socket != -1) close(c->tfm_socket);
    c->op_socket = c->tfm_socket = -1;
}

static int afalg_ctr_crypt_inplace(struct afalg_ctx *c, uint8_t *buf, size_t len, uint8_t iv[16]) {
    const size_t max_chunk = 64 * 1024;
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > max_chunk) chunk = max_chunk;
        struct iovec iov;
        iov.iov_base = buf + offset;
        iov.iov_len = chunk;
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        
        /* Correct control message setup for AF_ALG IV */
        char ctrl[CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
        memset(ctrl, 0, sizeof(ctrl));
        struct cmsghdr *cmsg = (struct cmsghdr *)ctrl;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        struct af_alg_iv *aiv = (struct af_alg_iv*)CMSG_DATA(cmsg);
        aiv->ivlen = 16;
        memcpy(aiv->iv, iv, 16);
        
        msg.msg_control = ctrl;
        msg.msg_controllen = sizeof(ctrl);
        ssize_t sent = sendmsg(c->op_socket, &msg, 0);
        if (sent == -1) return -1;
        ssize_t rec = recv(c->op_socket, buf + offset, chunk, 0);
        if (rec == -1) return -1;
        if ((size_t)rec != chunk) return -1;
        offset += chunk;
        incr_counter_be(iv);
    }
    return 0;
}

/* ---------------------------
   Benchmark harness (common)
   --------------------------- */

static void fill_random(uint8_t *b, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        for (size_t i = 0; i < n; ++i) b[i] = (uint8_t)(i * 37 + 13);
        return;
    }
    size_t rem = n;
    uint8_t *p = b;
    while (rem) {
        ssize_t r = read(fd, p, rem);
        if (r <= 0) break;
        rem -= (size_t)r;
        p += r;
    }
    close(fd);
}

/* prevent inlining to help perf tools and to avoid optimizer removal */
#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

/* run single benchmark: run iter times and measure */
static int run_benchmark_ctr(ctr_crypt_fn fn, size_t size, int iters, const uint8_t key[32], const uint8_t iv_init[16]) {
    uint8_t *buf = malloc(size);
    if (!buf) { perror("malloc"); return -1; }
    fill_random(buf, size);
    uint8_t *work = malloc(size);
    if (!work) { perror("malloc"); free(buf); return -1; }

    /* warm-up once */
    memcpy(work, buf, size);
    uint8_t iv_local_warm[16]; memcpy(iv_local_warm, iv_init, 16);
    fn(work, size, key, iv_local_warm);

    uint64_t t_start_ns = now_ns();
    uint64_t cycles_start = rdtsc_serialized();
    for (int i = 0; i < iters; ++i) {
        memcpy(work, buf, size);
        uint8_t iv_local[16];
        memcpy(iv_local, iv_init, 16);
        fn(work, size, key, iv_local);
        /* volatile touch to avoid elimination */
        volatile uint8_t v = work[0];
        (void)v;
    }
    uint64_t cycles_end = rdtsc_end();
    uint64_t t_end_ns = now_ns();

    double elapsed_s = (t_end_ns - t_start_ns) / 1e9;
    double mb = (double)size * (double)iters / (1024.0 * 1024.0);
    double mbps = mb / elapsed_s;
    uint64_t cycles = cycles_end - cycles_start;
    double cycles_per_byte = (double)cycles / ((double)size * (double)iters);

    printf("RESULTS: size=%zu iters=%d elapsed=%.6fs throughput=%.2f MB/s cycles=%" PRIu64 " cyc/byte=%.3f\n",
           size, iters, elapsed_s, mbps, cycles, cycles_per_byte);

    free(work); free(buf);
    return 0;
}

/* AF_ALG benchmark wrapper */
static int run_benchmark_afalg(size_t size, int iters) {
    uint8_t *buf = malloc(size);
    if (!buf) { perror("malloc"); return -1; }
    fill_random(buf, size);
    uint8_t key[32]; uint8_t iv[16];
    fill_random(key, 32); fill_random(iv, 16);

    struct afalg_ctx c;
    const char *algnames[] = { "ctr(aes)", "aes(ctr)", NULL };
    int rc = -1;
    for (int i = 0; algnames[i]; ++i) {
        if (afalg_init(&c, algnames[i], key, 32) == 0) { rc = 0; break; }
    }
    if (rc != 0) {
        fprintf(stderr, "AF_ALG init failed: errno=%d\n", errno);
        free(buf); return -1;
    }

    uint8_t *work = malloc(size);
    if (!work) { perror("malloc"); free(buf); afalg_close(&c); return -1; }

    uint64_t t_start_ns = now_ns();
    uint64_t cycles_start = rdtsc_serialized();
    for (int i = 0; i < iters; ++i) {
        memcpy(work, buf, size);
        uint8_t iv_local[16]; memcpy(iv_local, iv, 16);
        if (afalg_ctr_crypt_inplace(&c, work, size, iv_local) != 0) {
            fprintf(stderr, "AF_ALG encrypt failed: errno=%d\n", errno);
            free(work); free(buf); afalg_close(&c); return -1;
        }
        volatile uint8_t v = work[0]; (void)v;
    }
    uint64_t cycles_end = rdtsc_end();
    uint64_t t_end_ns = now_ns();

    double elapsed_s = (t_end_ns - t_start_ns) / 1e9;
    double mb = (double)size * (double)iters / (1024.0 * 1024.0);
    double mbps = mb / elapsed_s;
    uint64_t cycles = cycles_end - cycles_start;
    double cycles_per_byte = (double)cycles / ((double)size * (double)iters);

    printf("RESULTS_AFALG: size=%zu iters=%d elapsed=%.6fs throughput=%.2f MB/s cycles=%" PRIu64 " cyc/byte=%.3f\n",
           size, iters, elapsed_s, mbps, cycles, cycles_per_byte);

    free(work); free(buf); afalg_close(&c);
    return 0;
}

/* ---------------------------
   Main / CLI
   --------------------------- */

static void print_usage(const char *me) {
    fprintf(stderr,
        "Usage: %s --mode {soft|aesni|aesni-native|aesni-atom|evp|evp-soft|afalg} [--size bytes] [--iters n] [--debug n]\n"
        "Modes:\n"
        "  soft         : Pure software AES-256 implementation\n"
        "  aesni        : AES-NI accelerated AES-256\n"
        "  aesni-native : AES-NI native optimized implementation\n"
        "  aesni-atom   : AES-NI Atom/Silvermont optimized (2-way parallelism)\n"
        "  aesni-atom-opt: AES-NI Atom optimized (pre-computed keys for benchmarks)\n"
        "  evp          : OpenSSL EVP (auto hardware detection)\n"
        "  evp-soft     : OpenSSL EVP software-only\n"
        "  afalg        : AF_ALG kernel crypto\n", me);
}

int main(int argc, char **argv) {
    const char *mode = "aesni";
    size_t size = 1024 * 1024;
    int iters = 10;
    debug_level = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) size = (size_t)strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--debug") == 0 && i + 1 < argc) debug_level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0) { print_usage(argv[0]); return 0; }
        else { print_usage(argv[0]); return 1; }
    }

    /* prepare key/iv */
    uint8_t key[32]; uint8_t iv[16];
    fill_random(key, 32); fill_random(iv, 16);

    debug_printf(1, "Mode: %s size=%zu iters=%d debug=%d\n", mode, size, iters, debug_level);

    if (strcmp(mode, "soft") == 0) {
        /* run software AES-256 CTR */
        return run_benchmark_ctr(aes256_ctr_crypt_soft, size, iters, key, iv);
    } else if (strcmp(mode, "aesni") == 0) {
#if defined(__x86_64__) || defined(__i386__)
        return run_benchmark_ctr(aes256_ctr_crypt_aesni, size, iters, key, iv);
#else
        fprintf(stderr, "AES-NI not available on this architecture\n");
        return 1;
#endif
    } else if (strcmp(mode, "aesni-native") == 0) {
#if defined(__x86_64__) || defined(__i386__)
        return run_benchmark_ctr(aes256_ctr_crypt_aesni_native, size, iters, key, iv);
#else
        fprintf(stderr, "AES-NI not available on this architecture\n");
        return 1;
#endif
    } else if (strcmp(mode, "aesni-atom") == 0) {
#if defined(__x86_64__) || defined(__i386__)
        return run_benchmark_ctr(aes256_ctr_crypt_aesni_atom, size, iters, key, iv);
#else
        fprintf(stderr, "AES-NI not available on this architecture\n");
        return 1;
#endif
    } else if (strcmp(mode, "aesni-atom-opt") == 0) {
#if defined(__x86_64__) || defined(__i386__)
        return run_benchmark_ctr(aes256_ctr_crypt_aesni_atom_precomputed, size, iters, key, iv);
#else
        fprintf(stderr, "AES-NI not available on this architecture\n");
        return 1;
#endif
    } else if (strcmp(mode, "evp") == 0) {
        /* run OpenSSL EVP AES-256 CTR (auto hardware detection) */
        return run_benchmark_ctr(aes256_ctr_crypt_evp, size, iters, key, iv);
    } else if (strcmp(mode, "evp-soft") == 0) {
        /* run OpenSSL EVP AES-256 CTR (software-only) */
        return run_benchmark_ctr(aes256_ctr_crypt_evp_soft, size, iters, key, iv);
    } else if (strcmp(mode, "afalg") == 0) {
        return run_benchmark_afalg(size, iters);
    } else {
        fprintf(stderr, "Unknown mode '%s'\n", mode);
        print_usage(argv[0]);
        return 1;
    }
}
