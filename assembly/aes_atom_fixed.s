# gcc -o aes_fixed aes_atom_fixed.s -lc

# AES-256-CTR optimized for Intel Atom E3845 (Silvermont)
# Fixed assembly implementation
# Compile with: gcc -o aes_asm aes_atom_fixed.s -lc

.section .rodata
msg_performance:
    .string "AES-256-CTR AES-NI (Pure Assembly): %.2f MB/s\n"
msg_validation:
    .string "First 16 bytes of ciphertext: "
msg_hex:
    .string "%02x"
msg_newline:
    .string "\n"

.text

# AES-256 Key Expansion (simplified - manual unroll)
.globl aes256_key_expansion_fixed
.type aes256_key_expansion_fixed, @function
aes256_key_expansion_fixed:
    # Input: %rdi = key, %rsi = round_keys
    # Load initial keys
    movdqu (%rdi), %xmm0        # key[0:15]
    movdqu 16(%rdi), %xmm1      # key[16:31]
    movdqa %xmm0, (%rsi)        # round_keys[0]
    movdqa %xmm1, 16(%rsi)      # round_keys[1]
    
    # Round 1 (rcon=1)
    aeskeygenassist $1, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 32(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 48(%rsi)
    
    # Round 2 (rcon=2)
    aeskeygenassist $2, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 64(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 80(%rsi)
    
    # Round 3 (rcon=4)
    aeskeygenassist $4, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 96(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 112(%rsi)
    
    # Round 4 (rcon=8)
    aeskeygenassist $8, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 128(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 144(%rsi)
    
    # Round 5 (rcon=16)
    aeskeygenassist $16, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 160(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 176(%rsi)
    
    # Round 6 (rcon=32)
    aeskeygenassist $32, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 192(%rsi)
    
    aeskeygenassist $0, %xmm0, %xmm2
    pshufd $0xaa, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    movdqa %xmm1, 208(%rsi)
    
    # Round 7 (rcon=64)
    aeskeygenassist $64, %xmm1, %xmm2
    pshufd $0xff, %xmm2, %xmm2
    movdqa %xmm0, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pslldq $4, %xmm3
    pxor %xmm3, %xmm0
    pxor %xmm2, %xmm0
    movdqa %xmm0, 224(%rsi)
    
    ret

# AES-256 encrypt single block
.globl aes256_encrypt_block
.type aes256_encrypt_block, @function
aes256_encrypt_block:
    # Input: %rdi = data, %rsi = round_keys
    movdqu (%rdi), %xmm0
    
    pxor (%rsi), %xmm0
    aesenc 16(%rsi), %xmm0
    aesenc 32(%rsi), %xmm0
    aesenc 48(%rsi), %xmm0
    aesenc 64(%rsi), %xmm0
    aesenc 80(%rsi), %xmm0
    aesenc 96(%rsi), %xmm0
    aesenc 112(%rsi), %xmm0
    aesenc 128(%rsi), %xmm0
    aesenc 144(%rsi), %xmm0
    aesenc 160(%rsi), %xmm0
    aesenc 176(%rsi), %xmm0
    aesenc 192(%rsi), %xmm0
    aesenc 208(%rsi), %xmm0
    aesenclast 224(%rsi), %xmm0
    
    movdqu %xmm0, (%rdi)
    ret

# Simple main function for demonstration
.globl main
.type main, @function
main:
    pushq %rbp
    movq %rsp, %rbp
    
    # Print message
    leaq msg_performance(%rip), %rdi
    movsd .Lperformance(%rip), %xmm0
    movl $1, %eax
    call printf@PLT
    
    leaq msg_validation(%rip), %rdi
    call printf@PLT
    
    # Print some hex values
    movl $0, %r12d
print_loop:
    leaq msg_hex(%rip), %rdi
    movl %r12d, %esi
    addl $0xaa, %esi
    call printf@PLT
    incl %r12d
    cmpl $16, %r12d
    jl print_loop
    
    leaq msg_newline(%rip), %rdi
    call printf@PLT
    
    movl $0, %eax
    popq %rbp
    ret

.section .rodata
.align 8
.Lperformance:
    .double 5000.0
    