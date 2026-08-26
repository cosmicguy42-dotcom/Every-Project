/*
 * OUIJA Security Core - x86_64 Assembly Primitives
 * Designed for maximum security, constant-time execution, and side-channel resistance.
 */

.text
.global ouija_otp_xor_asm
.global ouija_ct_memcmp_asm
.global ouija_secure_memzero_asm

# ============================================================================
# Function: ouija_otp_xor_asm
# Prototype: void ouija_otp_xor_asm(const uint8_t *src, const uint8_t *pad, uint8_t *dst, size_t len);
# Arguments (System V AMD64 ABI):
#   %rdi = src (pointer to input data)
#   %rsi = pad (pointer to one-time pad)
#   %rdx = dst (pointer to output buffer)
#   %rcx = len (length in bytes)
# ============================================================================
ouija_otp_xor_asm:
    testq %rcx, %rcx
    jz .L_otp_done

    # Process 64-bit chunks
.L_otp_loop_qwords:
    cmpq $8, %rcx
    jb .L_otp_loop_bytes

    # Load 64-bit qword from src and pad, XOR, store to dst
    movq (%rdi), %r8
    movq (%rsi), %r9
    xorq %r8, %r9
    movq %r9, (%rdx)

    addq $8, %rdi
    addq $8, %rsi
    addq $8, %rdx
    subq $8, %rcx
    jmp .L_otp_loop_qwords

.L_otp_loop_bytes:
    testq %rcx, %rcx
    jz .L_otp_done

    movb (%rdi), %r8b
    movb (%rsi), %r9b
    xorb %r8b, %r9b
    movb %r9b, (%rdx)

    incq %rdi
    incq %rsi
    incq %rdx
    decq %rcx
    jmp .L_otp_loop_bytes

.L_otp_done:
    # Memory barrier to ensure stores are committed
    mfence
    # Zero out scratch registers
    xorq %r8, %r8
    xorq %r9, %r9
    ret


# ============================================================================
# Function: ouija_ct_memcmp_asm
# Prototype: int ouija_ct_memcmp_asm(const uint8_t *a, const uint8_t *b, size_t len);
# Arguments:
#   %rdi = a (pointer to buffer A)
#   %rsi = b (pointer to buffer B)
#   %rdx = len (length in bytes)
# Returns:
#   %rax = 0 if identical, non-zero if different (constant-time)
# ============================================================================
ouija_ct_memcmp_asm:
    xorq %rax, %rax        # Accumulator for differences
    testq %rdx, %rdx
    jz .L_ct_done

.L_ct_loop:
    movb (%rdi), %r8b
    movb (%rsi), %r9b
    xorb %r8b, %r9b        # %r9b = a[i] ^ b[i]
    movzbq %r9b, %r10
    orq %r10, %rax         # Accumulate difference into %rax without branching

    incq %rdi
    incq %rsi
    decq %rdx
    jnz .L_ct_loop

.L_ct_done:
    # Clean scratch registers
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    ret


# ============================================================================
# Function: ouija_secure_memzero_asm
# Prototype: void ouija_secure_memzero_asm(void *ptr, size_t len);
# Arguments:
#   %rdi = ptr (pointer to memory to zeroize)
#   %rsi = len (length in bytes)
# Guaranteed not to be removed by compiler optimization.
# ============================================================================
ouija_secure_memzero_asm:
    testq %rsi, %rsi
    jz .L_zero_done
    xorq %rax, %rax

.L_zero_qwords:
    cmpq $8, %rsi
    jb .L_zero_bytes
    movq %rax, (%rdi)
    addq $8, %rdi
    subq $8, %rsi
    jmp .L_zero_qwords

.L_zero_bytes:
    testq %rsi, %rsi
    jz .L_zero_done
    movb %al, (%rdi)
    incq %rdi
    decq %rsi
    jmp .L_zero_bytes

.L_zero_done:
    # Memory serialization fence
    mfence
    ret

# GNU stack note to prevent executable stack warning
.section .note.GNU-stack,"",@progbits
