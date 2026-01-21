//! Early boot timing for the dynamic linker
//!
//! This module provides timing output that works before the C library is initialized.
//! It uses raw syscalls to write timestamps to stderr.
//!
//! Output format: BOOT:<relative_ms>:<phase>:<detail>
//!
//! Enable with: export LD_BOOT_TIMING=1 (checked via auxv, not getenv)
//! Or always enabled during development by setting ALWAYS_ENABLED = true

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Set to true to always emit boot timing (for development)
const ALWAYS_ENABLED: bool = false;

/// Whether timing is enabled (checked once at startup)
static ENABLED: AtomicBool = AtomicBool::new(ALWAYS_ENABLED);

/// Boot start time in nanoseconds
static BOOT_START: AtomicU64 = AtomicU64::new(0);

/// Initialize boot timing - call once at the very start of ld.so
pub fn init() {
    if !ALWAYS_ENABLED {
        return;
    }
    let now = timestamp_ns();
    BOOT_START.store(now, Ordering::SeqCst);
}

/// Get current monotonic timestamp in nanoseconds using raw syscall
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

/// Get elapsed time since boot start in nanoseconds
#[inline]
fn elapsed_ns() -> u64 {
    let now = timestamp_ns();
    let start = BOOT_START.load(Ordering::Relaxed);
    now.saturating_sub(start)
}

/// Write a string to stderr using raw syscall
fn write_stderr(s: &[u8]) {
    unsafe {
        let _ = syscall::syscall3(
            syscall::SYS_WRITE,
            2, // stderr
            s.as_ptr() as usize,
            s.len(),
        );
    }
}

/// Format a u64 as decimal into buffer, return slice
fn format_u64(buf: &mut [u8], mut val: u64) -> &[u8] {
    if val == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }

    let mut i = 0;
    let mut tmp = [0u8; 20];
    while val > 0 && i < 20 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }

    // Reverse into buf
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    &buf[..i]
}

/// Log a boot timing event
/// phase: High-level category (e.g., "init", "load", "resolve")
/// detail: Specific operation (e.g., "tcb", "relibc.so", "printf")
pub fn log(phase: &str, detail: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let elapsed = elapsed_ns();
    let elapsed_us = elapsed / 1_000; // Convert to microseconds for readability

    // Format: BOOT:<elapsed_us>:<phase>:<detail>\n
    let mut buf = [0u8; 256];
    let mut pos = 0;

    // "BOOT:"
    buf[pos..pos+5].copy_from_slice(b"BOOT:");
    pos += 5;

    // elapsed_us
    let mut num_buf = [0u8; 20];
    let num = format_u64(&mut num_buf, elapsed_us);
    buf[pos..pos+num.len()].copy_from_slice(num);
    pos += num.len();

    buf[pos] = b':';
    pos += 1;

    // phase
    let phase_bytes = phase.as_bytes();
    let phase_len = phase_bytes.len().min(50);
    buf[pos..pos+phase_len].copy_from_slice(&phase_bytes[..phase_len]);
    pos += phase_len;

    buf[pos] = b':';
    pos += 1;

    // detail
    let detail_bytes = detail.as_bytes();
    let detail_len = detail_bytes.len().min(100);
    buf[pos..pos+detail_len].copy_from_slice(&detail_bytes[..detail_len]);
    pos += detail_len;

    buf[pos] = b'\n';
    pos += 1;

    write_stderr(&buf[..pos]);
}

/// Log with duration (for timed sections)
pub fn log_duration(phase: &str, detail: &str, duration_ns: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let elapsed = elapsed_ns();
    let elapsed_us = elapsed / 1_000;
    let duration_us = duration_ns / 1_000;

    // Format: BOOT:<elapsed_us>:<phase>:<detail>:<duration_us>us\n
    let mut buf = [0u8; 256];
    let mut pos = 0;

    // "BOOT:"
    buf[pos..pos+5].copy_from_slice(b"BOOT:");
    pos += 5;

    // elapsed_us
    let mut num_buf = [0u8; 20];
    let num = format_u64(&mut num_buf, elapsed_us);
    buf[pos..pos+num.len()].copy_from_slice(num);
    pos += num.len();

    buf[pos] = b':';
    pos += 1;

    // phase
    let phase_bytes = phase.as_bytes();
    let phase_len = phase_bytes.len().min(40);
    buf[pos..pos+phase_len].copy_from_slice(&phase_bytes[..phase_len]);
    pos += phase_len;

    buf[pos] = b':';
    pos += 1;

    // detail
    let detail_bytes = detail.as_bytes();
    let detail_len = detail_bytes.len().min(80);
    buf[pos..pos+detail_len].copy_from_slice(&detail_bytes[..detail_len]);
    pos += detail_len;

    buf[pos] = b':';
    pos += 1;

    // duration_us
    let num = format_u64(&mut num_buf, duration_us);
    buf[pos..pos+num.len()].copy_from_slice(num);
    pos += num.len();

    // "us"
    buf[pos..pos+2].copy_from_slice(b"us");
    pos += 2;

    buf[pos] = b'\n';
    pos += 1;

    write_stderr(&buf[..pos]);
}

/// Start timing a section, returns current timestamp
#[inline]
pub fn start() -> u64 {
    if ENABLED.load(Ordering::Relaxed) {
        timestamp_ns()
    } else {
        0
    }
}

/// End timing and log
#[inline]
pub fn end(start_time: u64, phase: &str, detail: &str) {
    if start_time == 0 {
        return;
    }
    let duration = timestamp_ns().saturating_sub(start_time);
    log_duration(phase, detail, duration);
}

/// Macro for timing a block
#[macro_export]
macro_rules! boot_timed {
    ($phase:expr, $detail:expr, $body:expr) => {{
        let _start = $crate::ld_so::boot_timing::start();
        let _result = $body;
        $crate::ld_so::boot_timing::end(_start, $phase, $detail);
        _result
    }};
}
