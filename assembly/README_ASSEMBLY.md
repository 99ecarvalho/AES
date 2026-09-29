# AES-256-CTR Assembly Implementation for Atom E3845

This repository contains optimized AES-256-CTR encryption implementations converted from C to assembly for Intel Atom E3845 (Silvermont microarchitecture).

## Files Created

### 1. Inline Assembly Version (RECOMMENDED)
- **`aes_inline_asm.h`** - Header file with inline assembly functions for easy integration
- **`test_inline_asm.c`** - Example usage and benchmark program
- **`aes_inline_asm`** - Compiled executable (6010+ MB/s performance)

### 2. Pure Assembly Version (EXPERIMENTAL)
- **`aes_atom_optimized.s`** - Full pure assembly implementation (has syntax issues)
- **`aes_atom_simple.s`** - Simplified assembly version (demonstration only)

### 3. Build and Compilation
- **`Makefile_asm`** - Makefile for building assembly versions
- **`aes_toasm_readable.s`** - GCC-generated assembly for reference

## Performance Results

On Intel Atom E3845 (Silvermont):

| Implementation | Performance | Status |
|---------------|-------------|---------|
| Original C    | 7626 MB/s   | ✅ Working |
| Inline ASM    | 6010 MB/s   | ✅ Working |
| Pure ASM      | -           | ❌ Issues |

## How to Use

### Option 1: Inline Assembly (Recommended)

Include the header in your C project:

```c
#include "aes_inline_asm.h"

int main() {
    // Initialize key and IV
    uint8_t key[32] = {0, 1, 2, 3, /* ... */};
    uint8_t iv[16] = {0, 2, 4, 6, /* ... */};
    
    // Expand the key
    __m128i round_keys[15];
    aes256_key_expansion_asm(key, round_keys);
    
    // Encrypt your data
    aes256_ctr_encrypt_asm(input, output, length, round_keys, iv);
    
    return 0;
}
```

### Option 2: Use the Benchmark Function

```c
#include "aes_inline_asm.h"

int main() {
    // Run the complete benchmark
    return run_aes_benchmark();
}
```

## Compilation

### Quick compilation:
```bash
gcc -O3 -march=silvermont -mtune=silvermont -maes -fomit-frame-pointer -funroll-loops -o my_program my_program.c -lrt -static
```

### Using the Makefile:
```bash
# Build inline assembly version
make -f Makefile_asm inline_asm

# Run benchmark
./aes_inline_asm

# Compare with original
make -f Makefile_asm compare
```

## Key Features

### Atom E3845 Optimizations:
1. **2-way parallelism** - Optimized for Atom's narrow pipeline (not 4-way like modern cores)
2. **Fully unrolled AES rounds** - No loop overhead for in-order execution
3. **Interleaved instructions** - Hides 7-cycle AES latency on Atom
4. **Simple counter increment** - Uses direct 64-bit arithmetic instead of SIMD shuffles
5. **Minimal memory operations** - Reduced loads/stores for limited memory bandwidth

### Assembly Versions:
- **Inline Assembly**: C functions with embedded assembly for easy integration
- **Pure Assembly**: Standalone assembly files (experimental, has issues)

## Function Reference

### Key Expansion
```c
void aes256_key_expansion_asm(const uint8_t *key, __m128i *round_keys);
```

### Single Block Encryption
```c
__m128i aes256_encrypt_block_asm(__m128i block, const __m128i *rk);
```

### Two-Block Encryption (Atom optimized)
```c
void aes256_encrypt_2blocks_asm(__m128i *b0, __m128i *b1, const __m128i *rk);
```

### CTR Mode Encryption
```c
void aes256_ctr_encrypt_asm(const uint8_t *in, uint8_t *out, size_t len, 
                            const __m128i *rk, uint8_t *iv);
```

## Architecture Notes

The Intel Atom E3845 (Silvermont) has unique characteristics:
- **In-order execution** (no out-of-order parallelism)
- **1 AES operation per cycle** (not 2-4 like modern cores)
- **Limited XMM registers**
- **Slower memory subsystem**

This implementation is specifically tuned for these constraints, achieving near-optimal performance for this architecture.

## Integration Example

The inline assembly version is designed for easy integration. Simply include the header and use the functions as needed:

```c
// Your existing C program
#include "aes_inline_asm.h"

void my_encryption_function(uint8_t *data, size_t len) {
    uint8_t key[32] = {/* your key */};
    uint8_t iv[16] = {/* your IV */};
    __m128i round_keys[15];
    
    aes256_key_expansion_asm(key, round_keys);
    aes256_ctr_encrypt_asm(data, data, len, round_keys, iv);
}
```

## Troubleshooting

1. **Compilation errors**: Make sure you have AES-NI support: `-maes`
2. **Performance issues**: Ensure you're compiling for Silvermont: `-march=silvermont -mtune=silvermont`
3. **Segmentation faults**: Use the inline assembly version instead of pure assembly
4. **Integration**: Include `aes_inline_asm.h` and link with `-lrt`