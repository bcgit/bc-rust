//! A call made with the registers zero, for the SM2 and ECDSA stack harnesses, each of which
//! includes this file as its `scrubbed` module. This program computes with the secrets it searches
//! for (to know what to search for, and to check the operation's output), and a word of one can
//! wait in a register of `main` across the call that runs the operation: in a callee-saved one,
//! which the first frame below that uses it saves, or in a caller-saved one that the harness's
//! own frames above the operation leave alone, which a prologue can store as well (an argument
//! register it was not passed, as the half of an `Option` a `None` leaves unset). Either way the
//! copy the search then finds is this program's and not the operation's. A Rust function cannot
//! clear those registers, so this is a few lines of assembly: it saves the callee-saved ones in
//! its own frame, above every frame searched, zeroes them and every caller-saved register but
//! the two carrying the target and its argument, makes the call and restores the callee-saved
//! ones.
//!
//! aarch64 (AAPCS64): callee-saved x19-x28 and the low halves of v8-v15; caller-saved x1-x15,
//! x17 and v0-v31 (x16 carries the target, x0 the argument; x18, the platform register, is left).
//! x86-64 (System V): callee-saved rbx, rbp and r12-r15; caller-saved rsi, rdx, rcx, r8-r11 and
//! xmm0-xmm15 (rax carries the target, rdi the argument). The upper halves of the AVX registers
//! are left, AVX not being baseline.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".text",
    ".globl stack_harness_scrubbed_call",
    ".type stack_harness_scrubbed_call, %function",
    ".p2align 2",
    "stack_harness_scrubbed_call:",
    "stp x29, x30, [sp, #-160]!",
    "mov x29, sp",
    "stp x19, x20, [sp, #16]",
    "stp x21, x22, [sp, #32]",
    "stp x23, x24, [sp, #48]",
    "stp x25, x26, [sp, #64]",
    "stp x27, x28, [sp, #80]",
    "stp d8, d9, [sp, #96]",
    "stp d10, d11, [sp, #112]",
    "stp d12, d13, [sp, #128]",
    "stp d14, d15, [sp, #144]",
    "mov x16, x0",
    "mov x0, x1",
    "mov x19, xzr",
    "mov x20, xzr",
    "mov x21, xzr",
    "mov x22, xzr",
    "mov x23, xzr",
    "mov x24, xzr",
    "mov x25, xzr",
    "mov x26, xzr",
    "mov x27, xzr",
    "mov x28, xzr",
    "movi v8.16b, #0",
    "movi v9.16b, #0",
    "movi v10.16b, #0",
    "movi v11.16b, #0",
    "movi v12.16b, #0",
    "movi v13.16b, #0",
    "movi v14.16b, #0",
    "movi v15.16b, #0",
    // The caller-saved registers but x0 (the argument) and x16 (the target), which a
    // callee's prologue can also store, as it does argument registers it was not passed.
    "mov x1, xzr",
    "mov x2, xzr",
    "mov x3, xzr",
    "mov x4, xzr",
    "mov x5, xzr",
    "mov x6, xzr",
    "mov x7, xzr",
    "mov x8, xzr",
    "mov x9, xzr",
    "mov x10, xzr",
    "mov x11, xzr",
    "mov x12, xzr",
    "mov x13, xzr",
    "mov x14, xzr",
    "mov x15, xzr",
    "mov x17, xzr",
    "movi v0.16b, #0",
    "movi v1.16b, #0",
    "movi v2.16b, #0",
    "movi v3.16b, #0",
    "movi v4.16b, #0",
    "movi v5.16b, #0",
    "movi v6.16b, #0",
    "movi v7.16b, #0",
    "movi v16.16b, #0",
    "movi v17.16b, #0",
    "movi v18.16b, #0",
    "movi v19.16b, #0",
    "movi v20.16b, #0",
    "movi v21.16b, #0",
    "movi v22.16b, #0",
    "movi v23.16b, #0",
    "movi v24.16b, #0",
    "movi v25.16b, #0",
    "movi v26.16b, #0",
    "movi v27.16b, #0",
    "movi v28.16b, #0",
    "movi v29.16b, #0",
    "movi v30.16b, #0",
    "movi v31.16b, #0",
    "blr x16",
    "ldp d14, d15, [sp, #144]",
    "ldp d12, d13, [sp, #128]",
    "ldp d10, d11, [sp, #112]",
    "ldp d8, d9, [sp, #96]",
    "ldp x27, x28, [sp, #80]",
    "ldp x25, x26, [sp, #64]",
    "ldp x23, x24, [sp, #48]",
    "ldp x21, x22, [sp, #32]",
    "ldp x19, x20, [sp, #16]",
    "ldp x29, x30, [sp], #160",
    "ret",
    ".size stack_harness_scrubbed_call, . - stack_harness_scrubbed_call",
);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".text",
    ".globl stack_harness_scrubbed_call",
    ".type stack_harness_scrubbed_call, @function",
    ".p2align 4",
    "stack_harness_scrubbed_call:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // Six pushes and the return address: 8 more aligns the stack to 16 at the call.
    "sub rsp, 8",
    "mov rax, rdi",
    "mov rdi, rsi",
    "xor ebp, ebp",
    "xor ebx, ebx",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    // The caller-saved registers but rdi (the argument) and rax (the target), which a
    // callee's prologue can also store, as it does argument registers it was not passed.
    "xor esi, esi",
    "xor edx, edx",
    "xor ecx, ecx",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "pxor xmm0, xmm0",
    "pxor xmm1, xmm1",
    "pxor xmm2, xmm2",
    "pxor xmm3, xmm3",
    "pxor xmm4, xmm4",
    "pxor xmm5, xmm5",
    "pxor xmm6, xmm6",
    "pxor xmm7, xmm7",
    "pxor xmm8, xmm8",
    "pxor xmm9, xmm9",
    "pxor xmm10, xmm10",
    "pxor xmm11, xmm11",
    "pxor xmm12, xmm12",
    "pxor xmm13, xmm13",
    "pxor xmm14, xmm14",
    "pxor xmm15, xmm15",
    "call rax",
    "add rsp, 8",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".size stack_harness_scrubbed_call, . - stack_harness_scrubbed_call",
);

#[cfg(not(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))))]
compile_error!(
    "the stack harnesses clear the callee-saved registers on aarch64 and x86-64 Linux only"
);

unsafe extern "C" {
    /// Calls `job(arg)` with the callee-saved registers and every caller-saved register but the
    /// two that carry `job` and `arg` zero, and restores the callee-saved ones.
    fn stack_harness_scrubbed_call(job: extern "C" fn(*mut u8), arg: *mut u8);
}

/// Runs `f` with every callee-saved register and the caller-saved ones zero, its frames below one
/// of this module's that holds what the callee-saved registers held.
pub fn call<F: FnOnce()>(f: F) {
    extern "C" fn job<F: FnOnce()>(arg: *mut u8) {
        // SAFETY: `arg` is the `Option<F>` of `call`, alive and borrowed by nothing else until
        // the call returns. A panic here aborts, as a panic out of an `extern "C"` function does.
        let f = unsafe { &mut *arg.cast::<Option<F>>() };
        (f.take().unwrap())();
    }
    let mut f = Some(f);
    // SAFETY: the assembly above follows the C calling convention, restores every register it
    // changes that the convention asks it to keep, and passes `arg` on unchanged.
    unsafe { stack_harness_scrubbed_call(job::<F>, (&raw mut f).cast()) }
}
