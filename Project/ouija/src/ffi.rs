//! Safe Rust abstractions over C native security and x86_64 Assembly primitives.

#![allow(dead_code)]

use std::os::raw::{c_int, c_void};

extern "C" {
    /// x86_64 Assembly: Constant-time One-Time Pad XOR
    pub fn ouija_otp_xor_asm(src: *const u8, pad: *const u8, dst: *mut u8, len: usize);

    /// x86_64 Assembly: Constant-time memory comparison
    pub fn ouija_ct_memcmp_asm(a: *const u8, b: *const u8, len: usize) -> c_int;

    /// x86_64 Assembly: Fence-enforced secure memory zeroization
    pub fn ouija_secure_memzero_asm(ptr: *mut c_void, len: usize);

    /// C: Process hardening (PR_SET_DUMPABLE=0, RLIMIT_CORE=0)
    pub fn ouija_harden_process() -> c_int;

    /// C: Lock virtual pages in RAM (mlock)
    pub fn ouija_lock_memory(addr: *mut c_void, len: usize) -> c_int;

    /// C: Unlock virtual pages (munlock)
    pub fn ouija_unlock_memory(addr: *mut c_void, len: usize) -> c_int;

    /// C: Securely harvest entropy via Linux getrandom(2)
    pub fn ouija_secure_random(buf: *mut u8, len: usize) -> c_int;
}

/// Applies Linux process hardening to protect keys in memory against dump and ptrace.
pub fn harden_process() {
    unsafe {
        let res = ouija_harden_process();
        if res != 0 {
            eprintln!("[WARN] Process hardening returned non-zero code: {}", res);
        }
    }
}

/// Executes constant-time One-Time Pad XOR using assembly.
pub fn otp_xor_asm(src: &[u8], pad: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), pad.len(), "Source and Pad lengths must match");
    assert_eq!(src.len(), dst.len(), "Source and Destination lengths must match");
    if src.is_empty() {
        return;
    }
    unsafe {
        ouija_otp_xor_asm(src.as_ptr(), pad.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}

/// Constant-time memory comparison using assembly routine.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    unsafe {
        ouija_ct_memcmp_asm(a.as_ptr(), b.as_ptr(), a.len()) == 0
    }
}

/// Securely zeroize memory using assembly fences.
pub fn secure_zeroize(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe {
        ouija_secure_memzero_asm(buf.as_mut_ptr() as *mut c_void, buf.len());
    }
}

/// Lock memory slice in physical RAM.
pub fn lock_memory_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe {
        let _ = ouija_lock_memory(buf.as_ptr() as *mut c_void, buf.len());
    }
}

/// Unlock memory slice.
pub fn unlock_memory_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe {
        let _ = ouija_unlock_memory(buf.as_ptr() as *mut c_void, buf.len());
    }
}

/// Fill buffer with cryptographically secure random bytes from Linux getrandom(2).
pub fn fill_secure_random(buf: &mut [u8]) -> Result<(), String> {
    if buf.is_empty() {
        return Ok(());
    }
    unsafe {
        let res = ouija_secure_random(buf.as_mut_ptr(), buf.len());
        if res != 0 {
            return Err(format!("ouija_secure_random failed with errno {}", res));
        }
    }
    Ok(())
}
