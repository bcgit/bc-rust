//! A call made with every callee-saved register zero, for the SM2 and ECDSA stack harnesses, each
//! of which includes this file as its `scrubbed` module. This program computes with the secrets it
//! searches for (to know what to search for, and to check the operation's output), and a word
//! of one can wait in a callee-saved register of `main` across the call that runs the operation;
//! the first frame below that uses the register saves it, a copy the search then finds, which is
//! this program's and not the operation's. A Rust function cannot clear those registers, so this
//! is a few lines of assembly: it saves them in its own frame, above every frame searched, zeroes
//! them, makes the call and restores them.
//!
//! aarch64 (AAPCS64): x19-x28 and the low halves of v8-v15. x86-64 (System V): rbx, rbp and
//! r12-r15. The caller-saved registers are not touched: no callee saves those.

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
    /// Calls `job(arg)` with the callee-saved registers zero, and restores them.
    fn stack_harness_scrubbed_call(job: extern "C" fn(*mut u8), arg: *mut u8);
}

/// Runs `f` with every callee-saved register zero, its frames below one of this module's that
/// holds what those registers held.
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
