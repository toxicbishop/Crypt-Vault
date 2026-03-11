; ═══════════════════════════════════════════════════════════════════════════════
; Crypt Vault — Assembly Cryptographic Primitives (x64 MASM)
; 
; NOTE: This file is provided as a reference implementation.
;       The main application uses compiler intrinsics (SSE2, CPUID) for
;       cross-compiler compatibility. To use this file instead:
;       1. Install MASM (ml64.exe from Visual Studio)
;       2. Assemble: ml64 /c crypto_asm.asm
;       3. Link: cl Crypt-Vault.cpp crypto_asm.obj
;
; Functions:
;   - secure_memzero     : Secure memory wipe (prevents compiler optimization)
;   - xor_block          : XOR two 16-byte blocks (AES block XOR)
;   - check_aes_support  : CPUID check for AES-NI hardware support
;   - sha256_round       : Single SHA-256 compression round
;
; Calling Convention: Microsoft x64 (RCX, RDX, R8, R9)
; ═══════════════════════════════════════════════════════════════════════════════

.code

; ═══════════════════════════════════════════════════════════════════════════════
; secure_memzero - Secure Memory Wipe
; 
; Zeroes memory in a way that cannot be optimized away by the compiler.
; Uses volatile writes to ensure the operation is performed.
;
; void secure_memzero(void* ptr, size_t len)
;   RCX = ptr  (pointer to memory)
;   RDX = len  (number of bytes to zero)
;
; Returns: nothing
; ═══════════════════════════════════════════════════════════════════════════════
secure_memzero PROC
    push    rdi
    
    mov     rdi, rcx            ; destination pointer
    mov     rcx, rdx            ; count in RCX for rep
    xor     eax, eax            ; zero value
    
    ; Zero 8 bytes at a time
    mov     r8, rcx
    shr     rcx, 3              ; divide by 8
    rep     stosq               ; store quadwords
    
    ; Zero remaining bytes
    mov     rcx, r8
    and     rcx, 7              ; remaining bytes (mod 8)
    rep     stosb               ; store bytes
    
    ; Memory barrier to prevent reordering
    mfence
    
    pop     rdi
    ret
secure_memzero ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; xor_block - XOR Two 16-byte Blocks
;
; Performs XOR operation on two 16-byte AES blocks.
; Result is stored in the destination block.
;
; void xor_block(uint8_t* dest, const uint8_t* src)
;   RCX = dest (16-byte destination block, modified in place)
;   RDX = src  (16-byte source block)
;
; Returns: nothing
; ═══════════════════════════════════════════════════════════════════════════════
xor_block PROC
    ; Load 16 bytes from dest into XMM0
    movdqu  xmm0, [rcx]
    
    ; Load 16 bytes from src into XMM1
    movdqu  xmm1, [rdx]
    
    ; XOR the blocks
    pxor    xmm0, xmm1
    
    ; Store result back to dest
    movdqu  [rcx], xmm0
    
    ret
xor_block ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; xor_blocks_chain - XOR Multiple Blocks (for CBC mode)
;
; XORs src with iv, stores in dest. Useful for CBC chaining.
;
; void xor_blocks_chain(uint8_t* dest, const uint8_t* src, const uint8_t* iv, size_t num_blocks)
;   RCX = dest       (output buffer)
;   RDX = src        (input buffer) 
;   R8  = iv         (16-byte IV/previous block)
;   R9  = num_blocks (number of 16-byte blocks)
;
; Returns: nothing
; ═══════════════════════════════════════════════════════════════════════════════
xor_blocks_chain PROC
    test    r9, r9
    jz      done
    
    ; Load IV into XMM2
    movdqu  xmm2, [r8]
    
block_loop:
    ; Load source block
    movdqu  xmm0, [rdx]
    
    ; XOR with IV/previous ciphertext
    pxor    xmm0, xmm2
    
    ; Store to destination
    movdqu  [rcx], xmm0
    
    ; Update pointers
    add     rcx, 16
    add     rdx, 16
    
    ; For CBC, the IV for next block would be ciphertext
    ; (caller handles this for encryption, here we just do the XOR)
    
    dec     r9
    jnz     block_loop
    
done:
    ret
xor_blocks_chain ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; check_aes_support - CPUID Check for AES-NI Support
;
; Checks if the CPU supports AES-NI instructions using CPUID.
; AES-NI is indicated by bit 25 of ECX from CPUID with EAX=1.
;
; int check_aes_support(void)
;
; Returns: 1 if AES-NI supported, 0 otherwise
; ═══════════════════════════════════════════════════════════════════════════════
check_aes_support PROC
    push    rbx
    
    ; Check CPUID is supported (should be on all x64 CPUs)
    mov     eax, 1              ; CPUID function 1: processor info
    cpuid
    
    ; Check AES-NI bit (bit 25 of ECX)
    test    ecx, (1 SHL 25)
    jz      no_aes
    
    mov     eax, 1              ; AES-NI supported
    jmp     done
    
no_aes:
    xor     eax, eax            ; AES-NI not supported
    
done:
    pop     rbx
    ret
check_aes_support ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; check_sha_support - CPUID Check for SHA-NI Support
;
; Checks if the CPU supports SHA extensions using CPUID.
; SHA is indicated by bit 29 of EBX from CPUID with EAX=7, ECX=0.
;
; int check_sha_support(void)
;
; Returns: 1 if SHA-NI supported, 0 otherwise
; ═══════════════════════════════════════════════════════════════════════════════
check_sha_support PROC
    push    rbx
    
    mov     eax, 7              ; CPUID function 7: extended features
    xor     ecx, ecx            ; sub-function 0
    cpuid
    
    ; Check SHA bit (bit 29 of EBX)
    test    ebx, (1 SHL 29)
    jz      no_sha
    
    mov     eax, 1              ; SHA-NI supported
    jmp     done_sha
    
no_sha:
    xor     eax, eax            ; SHA-NI not supported
    
done_sha:
    pop     rbx
    ret
check_sha_support ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; sha256_round - Single SHA-256 Compression Round
;
; Performs one round of SHA-256 compression function.
; This is the core operation repeated 64 times per block.
;
; void sha256_round(uint32_t* state, uint32_t k, uint32_t w)
;   RCX = state (pointer to 8 uint32_t state values: a,b,c,d,e,f,g,h)
;   EDX = k     (round constant K[i])
;   R8D = w     (message schedule word W[i])
;
; SHA-256 round function:
;   T1 = h + Σ1(e) + Ch(e,f,g) + k + w
;   T2 = Σ0(a) + Maj(a,b,c)
;   h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2
;
; Returns: nothing (state modified in place)
; ═══════════════════════════════════════════════════════════════════════════════
sha256_round PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Load state values
    mov     r9d,  [rcx]         ; a = state[0]
    mov     r10d, [rcx+4]       ; b = state[1]
    mov     r11d, [rcx+8]       ; c = state[2]
    mov     r12d, [rcx+12]      ; d = state[3]
    mov     r13d, [rcx+16]      ; e = state[4]
    mov     r14d, [rcx+20]      ; f = state[5]
    mov     r15d, [rcx+24]      ; g = state[6]
    mov     esi,  [rcx+28]      ; h = state[7]
    
    ; ─── Calculate Σ1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25) ───
    mov     eax, r13d
    ror     eax, 6
    mov     ebx, r13d
    ror     ebx, 11
    xor     eax, ebx
    mov     ebx, r13d
    ror     ebx, 25
    xor     eax, ebx            ; eax = Σ1(e)
    
    ; ─── Calculate Ch(e,f,g) = (e & f) ^ (~e & g) ───
    mov     ebx, r13d
    and     ebx, r14d           ; e & f
    mov     edi, r13d
    not     edi
    and     edi, r15d           ; ~e & g
    xor     ebx, edi            ; ebx = Ch(e,f,g)
    
    ; ─── T1 = h + Σ1(e) + Ch(e,f,g) + k + w ───
    add     eax, esi            ; + h
    add     eax, ebx            ; + Ch(e,f,g)
    add     eax, edx            ; + k
    add     eax, r8d            ; + w
    ; eax = T1
    
    ; ─── Calculate Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22) ───
    mov     ebx, r9d
    ror     ebx, 2
    mov     edi, r9d
    ror     edi, 13
    xor     ebx, edi
    mov     edi, r9d
    ror     edi, 22
    xor     ebx, edi            ; ebx = Σ0(a)
    
    ; ─── Calculate Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c) ───
    mov     edi, r9d
    and     edi, r10d           ; a & b
    push    rax                 ; save T1
    mov     eax, r9d
    and     eax, r11d           ; a & c
    xor     edi, eax
    mov     eax, r10d
    and     eax, r11d           ; b & c
    xor     edi, eax            ; edi = Maj(a,b,c)
    pop     rax                 ; restore T1
    
    ; ─── T2 = Σ0(a) + Maj(a,b,c) ───
    add     ebx, edi            ; ebx = T2
    
    ; ─── Update state: shift and compute new a and e ───
    ; h = g
    mov     [rcx+28], r15d
    ; g = f
    mov     [rcx+24], r14d
    ; f = e
    mov     [rcx+20], r13d
    ; e = d + T1
    add     r12d, eax
    mov     [rcx+16], r12d
    ; d = c
    mov     [rcx+12], r11d
    ; c = b
    mov     [rcx+8], r10d
    ; b = a
    mov     [rcx+4], r9d
    ; a = T1 + T2
    add     eax, ebx
    mov     [rcx], eax
    
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
sha256_round ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; rotate_right_32 - Helper: 32-bit rotate right
;
; uint32_t rotate_right_32(uint32_t value, int shift)
;   ECX = value
;   EDX = shift amount
;
; Returns: rotated value in EAX
; ═══════════════════════════════════════════════════════════════════════════════
rotate_right_32 PROC
    mov     eax, ecx
    mov     cl, dl              ; shift amount in cl
    ror     eax, cl
    ret
rotate_right_32 ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; constant_time_compare - Constant-time memory comparison
;
; Compares two buffers in constant time to prevent timing attacks.
;
; int constant_time_compare(const void* a, const void* b, size_t len)
;   RCX = a   (first buffer)
;   RDX = b   (second buffer)
;   R8  = len (number of bytes)
;
; Returns: 0 if equal, non-zero if different
; ═══════════════════════════════════════════════════════════════════════════════
constant_time_compare PROC
    xor     eax, eax            ; accumulator for differences
    test    r8, r8
    jz      cmp_done
    
cmp_loop:
    movzx   r9d, byte ptr [rcx]
    movzx   r10d, byte ptr [rdx]
    xor     r9d, r10d           ; difference (0 if same)
    or      eax, r9d            ; accumulate differences
    
    inc     rcx
    inc     rdx
    dec     r8
    jnz     cmp_loop
    
cmp_done:
    ret
constant_time_compare ENDP

END
