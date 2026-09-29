# gcc -o aes_fixed aes_atom_optimized.s -lc

# AES-256-CTR optimized for Intel Atom E3845 (Silvermont)
# Assembly implementation based on aes_toasm.c
# Compile with: gcc -o aes_asm aes_atom_optimized.s -lrt -static

.section .rodata
.align 16
rcon_table:
    .byte 1, 2, 4, 8, 16, 32, 64

msg_performance:
    .string "AES-256-CTR AES-NI (Atom optimized): %.2f MB/s\n"
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

# AES-256 encrypt single block (unrolled)
# Input: %xmm0 = block, %rdi = round_keys pointer
# Output: %xmm0 = encrypted block
.type aes256_encrypt_block, @function
aes256_encrypt_block:
    pxor (%rdi), %xmm0          # Initial round
    aesenc 16(%rdi), %xmm0      # Round 1
    aesenc 32(%rdi), %xmm0      # Round 2
    aesenc 48(%rdi), %xmm0      # Round 3
    aesenc 64(%rdi), %xmm0      # Round 4
    aesenc 80(%rdi), %xmm0      # Round 5
    aesenc 96(%rdi), %xmm0      # Round 6
    aesenc 112(%rdi), %xmm0     # Round 7
    aesenc 128(%rdi), %xmm0     # Round 8
    aesenc 144(%rdi), %xmm0     # Round 9
    aesenc 160(%rdi), %xmm0     # Round 10
    aesenc 176(%rdi), %xmm0     # Round 11
    aesenc 192(%rdi), %xmm0     # Round 12
    aesenc 208(%rdi), %xmm0     # Round 13
    aesenclast 224(%rdi), %xmm0 # Final round
    ret

# AES-256 encrypt 2 blocks (unrolled, interleaved for Atom)
# Input: %xmm0 = block0, %xmm1 = block1, %rdi = round_keys
# Output: %xmm0, %xmm1 = encrypted blocks
.type aes256_encrypt_2blocks, @function
aes256_encrypt_2blocks:
    # Initial round
    pxor (%rdi), %xmm0
    pxor (%rdi), %xmm1
    
    # Rounds 1-13 (interleaved to hide latency on Atom)
    aesenc 16(%rdi), %xmm0
    aesenc 16(%rdi), %xmm1
    aesenc 32(%rdi), %xmm0
    aesenc 32(%rdi), %xmm1
    aesenc 48(%rdi), %xmm0
    aesenc 48(%rdi), %xmm1
    aesenc 64(%rdi), %xmm0
    aesenc 64(%rdi), %xmm1
    aesenc 80(%rdi), %xmm0
    aesenc 80(%rdi), %xmm1
    aesenc 96(%rdi), %xmm0
    aesenc 96(%rdi), %xmm1
    aesenc 112(%rdi), %xmm0
    aesenc 112(%rdi), %xmm1
    aesenc 128(%rdi), %xmm0
    aesenc 128(%rdi), %xmm1
    aesenc 144(%rdi), %xmm0
    aesenc 144(%rdi), %xmm1
    aesenc 160(%rdi), %xmm0
    aesenc 160(%rdi), %xmm1
    aesenc 176(%rdi), %xmm0
    aesenc 176(%rdi), %xmm1
    aesenc 192(%rdi), %xmm0
    aesenc 192(%rdi), %xmm1
    aesenc 208(%rdi), %xmm0
    aesenc 208(%rdi), %xmm1
    
    # Final round
    aesenclast 224(%rdi), %xmm0
    aesenclast 224(%rdi), %xmm1
    ret

# AES-256-CTR encryption optimized for Atom E3845
# Input: %rdi = input, %rsi = output, %rdx = length, %rcx = round_keys, %r8 = iv
.type aes256_ctr_encrypt, @function
aes256_ctr_encrypt:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    
    # Load counter from IV
    movq 8(%r8), %r10           # ctr_low = iv[8:15]
    movq (%r8), %r11            # ctr_high = iv[0:7]
    
    # Setup pointers and calculate blocks
    movq %rdi, %r12             # input pointer
    movq %rsi, %r13             # output pointer
    movq %rdx, %r14             # remaining bytes
    shrq $4, %r14               # blocks = length / 16
    movq %rcx, %r15             # round_keys
    
ctr_main_loop:
    cmpq $2, %r14
    jl ctr_single_block
    
    # Build two counters
    movq %r11, %xmm0
    pinsrq $1, %r10, %xmm0      # counter 0
    
    incq %r10
    jnz no_carry1
    incq %r11
no_carry1:
    
    movq %r11, %xmm1
    pinsrq $1, %r10, %xmm1      # counter 1
    
    incq %r10
    jnz no_carry2
    incq %r11
no_carry2:
    
    # Encrypt both counters
    movq %r15, %rdi
    call aes256_encrypt_2blocks
    
    # Load input data and XOR with keystream
    movdqu (%r12), %xmm2
    movdqu 16(%r12), %xmm3
    pxor %xmm0, %xmm2
    pxor %xmm1, %xmm3
    
    # Store output
    movdqu %xmm2, (%r13)
    movdqu %xmm3, 16(%r13)
    
    # Advance pointers and decrement counter
    addq $32, %r12
    addq $32, %r13
    subq $2, %r14
    jmp ctr_main_loop
    
ctr_single_block:
    cmpq $0, %r14
    je ctr_done
    
    # Build single counter
    movq %r11, %xmm0
    pinsrq $1, %r10, %xmm0
    
    # Encrypt counter
    movq %r15, %rdi
    call aes256_encrypt_block
    
    # Load, XOR, store
    movdqu (%r12), %xmm1
    pxor %xmm0, %xmm1
    movdqu %xmm1, (%r13)
    
ctr_done:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

# Timer function using clock_gettime
.type now_sec, @function
now_sec:
    pushq %rbp
    movq %rsp, %rbp
    subq $32, %rsp              # Allocate space for timespec
    
    movq $1, %rdi               # CLOCK_MONOTONIC
    leaq -32(%rbp), %rsi        # &timespec
    movq $228, %rax             # sys_clock_gettime
    syscall
    
    # Convert to double: seconds + nanoseconds/1e9
    cvtsi2sd -32(%rbp), %xmm0   # tv_sec to double
    cvtsi2sd -24(%rbp), %xmm1   # tv_nsec to double
    movsd .Lnanosec_div(%rip), %xmm2
    divsd %xmm2, %xmm1          # tv_nsec / 1e9
    addsd %xmm1, %xmm0          # result = tv_sec + (tv_nsec/1e9)
    
    addq $32, %rsp
    popq %rbp
    ret

# Main function
.globl main
.type main, @function
main:
    pushq %rbp
    movq %rsp, %rbp
    subq $4200, %rsp            # Local space for keys, buffers, etc.
    
    # Initialize key (0,1,2,3...31)
    leaq -32(%rbp), %rdi        # key buffer
    movl $0, %ecx
init_key_loop:
    movb %cl, (%rdi,%rcx,1)
    incq %rcx
    cmpq $32, %rcx
    jl init_key_loop
    
    # Initialize IV (0,2,4,6...30)
    leaq -48(%rbp), %rdi        # iv buffer
    movl $0, %ecx
init_iv_loop:
    movl %ecx, %eax
    shlb $1, %al                # i * 2
    movb %al, (%rdi,%rcx,1)
    incq %rcx
    cmpq $16, %rcx
    jl init_iv_loop
    
    # Allocate input/output buffers (4MB each)
    movl $4194304, %edi         # SIZE = 4MB
    movl $12, %eax              # sys_brk
    syscall
    movq %rax, %r12             # input buffer base
    
    addq $4194304, %rdi
    movl $12, %eax              # sys_brk
    syscall
    movq %rax, %r13             # output buffer base
    
    # Initialize input buffer with 0xAA
    movq %r12, %rdi
    movl $0xAAAAAAAA, %eax
    movl $1048576, %ecx         # 4MB / 4
    rep stosl
    
    # Clear output buffer
    movq %r13, %rdi
    xorl %eax, %eax
    movl $1048576, %ecx
    rep stosl
    
    # Expand AES key
    leaq -32(%rbp), %rdi        # key
    leaq -288(%rbp), %rsi       # round_keys (15 * 16 = 240 bytes)
    call aes256_key_expansion_fixed
    
    # Warmup run
    movq %r12, %rdi             # input
    movq %r13, %rsi             # output  
    movl $4194304, %edx         # length
    leaq -288(%rbp), %rcx       # round_keys
    leaq -48(%rbp), %r8         # iv
    call aes256_ctr_encrypt
    
    # Start timing
    call now_sec
    movsd %xmm0, -296(%rbp)     # save start time
    
    # Benchmark loop (100 iterations)
    movl $0, %ebx
benchmark_loop:
    movq %r12, %rdi
    movq %r13, %rsi
    movl $4194304, %edx
    leaq -288(%rbp), %rcx
    leaq -48(%rbp), %r8
    call aes256_ctr_encrypt
    
    incl %ebx
    cmpl $100, %ebx
    jl benchmark_loop
    
    # End timing
    call now_sec
    movsd -296(%rbp), %xmm1     # load start time
    subsd %xmm1, %xmm0          # elapsed = end - start
    
    # Calculate MB/s: 100 * 4MB / elapsed / (1024*1024)
    movsd .Lhundred(%rip), %xmm1
    mulsd %xmm1, %xmm0          # 100 * elapsed
    movsd .Lsize_mb(%rip), %xmm1
    divsd %xmm0, %xmm1          # result
    
    # Print performance result
    leaq msg_performance(%rip), %rdi
    movl $1, %eax               # 1 XMM register used
    call printf
    
    # Print validation (first 16 bytes)
    leaq msg_validation(%rip), %rdi
    call printf
    
    movl $0, %ebx
print_hex_loop:
    leaq msg_hex(%rip), %rdi
    movzbl (%r13,%rbx), %esi
    call printf
    incl %ebx
    cmpl $16, %ebx
    jl print_hex_loop
    
    leaq msg_newline(%rip), %rdi
    call printf
    
    # Exit
    movl $0, %edi
    movl $60, %eax              # sys_exit
    syscall

# Constants section
.section .rodata
.align 8
.Lnanosec_div:
    .double 1000000000.0
.Lhundred:
    .double 100.0
.Lsize_mb:
    .double 4194304.0


