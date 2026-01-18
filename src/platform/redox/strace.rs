//! Syscall tracing for Redox OS
//!
//! When STRACE=1 environment variable is set, syscalls are logged to stderr.
//! Format: SYSCALL:timestamp:name:args:result:duration_ns

use core::{
    cell::Cell,
    fmt::Write as FmtWrite,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use alloc::string::String;

/// Whether tracing has been checked
static TRACE_CHECKED: AtomicBool = AtomicBool::new(false);
/// Whether tracing is enabled
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
/// File descriptor to write traces to (default: stderr = 2)
static TRACE_FD: AtomicUsize = AtomicUsize::new(2);

/// Thread-local recursion guard
#[thread_local]
static IN_TRACE: Cell<bool> = Cell::new(false);

/// Check environment and initialize tracing.
/// Safe to call multiple times - only checks once.
fn check_env() {
    if TRACE_CHECKED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Check STRACE environment variable
    // We use raw getenv to avoid recursion
    unsafe {
        extern "C" {
            fn getenv(name: *const i8) -> *mut i8;
        }

        let strace = getenv(b"STRACE\0".as_ptr() as *const i8);
        if !strace.is_null() && *strace == b'1' as i8 {
            TRACE_ENABLED.store(true, Ordering::SeqCst);

            // Check STRACE_FD
            let fd_str = getenv(b"STRACE_FD\0".as_ptr() as *const i8);
            if !fd_str.is_null() {
                let mut fd: usize = 0;
                let mut p = fd_str;
                while *p >= b'0' as i8 && *p <= b'9' as i8 {
                    fd = fd * 10 + (*p - b'0' as i8) as usize;
                    p = p.add(1);
                }
                if fd > 0 {
                    TRACE_FD.store(fd, Ordering::SeqCst);
                }
            }
        }
    }
}

/// Check if tracing is enabled
#[inline]
pub fn is_enabled() -> bool {
    check_env();
    TRACE_ENABLED.load(Ordering::Relaxed)
}

/// Enable tracing programmatically
pub fn enable(fd: usize) {
    TRACE_FD.store(fd, Ordering::SeqCst);
    TRACE_ENABLED.store(true, Ordering::SeqCst);
    TRACE_CHECKED.store(true, Ordering::SeqCst);
}

/// Disable tracing
pub fn disable() {
    TRACE_ENABLED.store(false, Ordering::SeqCst);
}

/// Get current monotonic timestamp in nanoseconds
#[inline]
fn timestamp_ns() -> u64 {
    let mut ts = syscall::TimeSpec::default();
    unsafe {
        let _ = syscall::syscall2(
            syscall::SYS_CLOCK_GETTIME,
            syscall::CLOCK_MONOTONIC,
            &mut ts as *mut _ as usize,
        );
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Write trace output
fn write_trace(msg: &str) {
    // Prevent recursion
    if IN_TRACE.get() {
        return;
    }
    IN_TRACE.set(true);

    let fd = TRACE_FD.load(Ordering::Relaxed);
    unsafe {
        let _ = syscall::syscall3(
            syscall::SYS_WRITE,
            fd,
            msg.as_ptr() as usize,
            msg.len(),
        );
    }

    IN_TRACE.set(false);
}

/// Log a syscall with timing
pub fn log_syscall(name: &str, args: &str, result: isize, start: u64) {
    if !is_enabled() {
        return;
    }

    let end = timestamp_ns();
    let duration = end.saturating_sub(start);

    let mut msg = String::with_capacity(256);
    let _ = write!(
        msg,
        "SYSCALL:{}:{}:{}:{}:{}\n",
        start, name, args, result, duration
    );

    write_trace(&msg);
}

/// Start timing a syscall
#[inline]
pub fn start() -> u64 {
    if is_enabled() {
        timestamp_ns()
    } else {
        0
    }
}

/// Log syscall entry (for debugging)
pub fn log_entry(name: &str, args: &str) {
    if !is_enabled() {
        return;
    }

    let ts = timestamp_ns();
    let mut msg = String::with_capacity(128);
    let _ = write!(msg, "ENTER:{}:{}:{}\n", ts, name, args);
    write_trace(&msg);
}
