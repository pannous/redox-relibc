//! Performance timing for Redox OS
//!
//! When STRACE_PERF=1 environment variable is set, timing data is logged.
//! Format: PERF:<timestamp_ns>:<phase>:<detail>:<duration_ns>

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Whether perf timing is enabled
static PERF_ENABLED: AtomicBool = AtomicBool::new(false);
/// Whether we've checked the environment
static PERF_CHECKED: AtomicBool = AtomicBool::new(false);
/// Session start time (for relative timestamps)
static SESSION_START: AtomicU64 = AtomicU64::new(0);

/// Check environment and initialize perf timing.
fn check_env() {
    if PERF_CHECKED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        unsafe extern "C" {
            fn getenv(name: *const i8) -> *mut i8;
        }

        let strace = getenv(b"STRACE\0".as_ptr() as *const i8);
        let strace_perf = getenv(b"STRACE_PERF\0".as_ptr() as *const i8);

        if (!strace.is_null() && *strace == b'1' as i8) ||
           (!strace_perf.is_null() && *strace_perf == b'1' as i8) {
            PERF_ENABLED.store(true, Ordering::SeqCst);
            SESSION_START.store(timestamp_ns(), Ordering::SeqCst);
        }
    }
}

/// Check if perf timing is enabled
#[inline]
pub fn is_enabled() -> bool {
    check_env();
    PERF_ENABLED.load(Ordering::Relaxed)
}

/// Enable perf timing programmatically
pub fn enable() {
    SESSION_START.store(timestamp_ns(), Ordering::SeqCst);
    PERF_ENABLED.store(true, Ordering::SeqCst);
    PERF_CHECKED.store(true, Ordering::SeqCst);
}

/// Get current monotonic timestamp in nanoseconds
#[inline]
pub fn timestamp_ns() -> u64 {
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

/// Get relative timestamp since session start
#[inline]
fn relative_ns() -> u64 {
    let now = timestamp_ns();
    let start = SESSION_START.load(Ordering::Relaxed);
    now.saturating_sub(start)
}

/// Write perf output to stderr
fn write_perf(msg: &str) {
    unsafe {
        let _ = syscall::syscall3(
            syscall::SYS_WRITE,
            2, // stderr
            msg.as_ptr() as usize,
            msg.len(),
        );
    }
}

/// Log a timed event
/// phase: Category of the event (e.g., "syscall", "ldso", "exec")
/// detail: Specific operation (e.g., "open", "mmap", "resolve")
/// duration_ns: Time spent in nanoseconds
pub fn log_event(phase: &str, detail: &str, duration_ns: u64) {
    if !is_enabled() {
        return;
    }

    let rel_time = relative_ns();

    // Format: PERF:<relative_time>:<phase>:<detail>:<duration>
    let mut buf = [0u8; 256];
    let len = format_perf_line(&mut buf, rel_time, phase, detail, duration_ns);

    write_perf(unsafe { core::str::from_utf8_unchecked(&buf[..len]) });
}

/// Log a phase start (for nested timing)
pub fn log_phase_start(phase: &str, detail: &str) {
    if !is_enabled() {
        return;
    }

    let rel_time = relative_ns();
    let mut buf = [0u8; 256];
    let len = format_start_line(&mut buf, rel_time, phase, detail);

    write_perf(unsafe { core::str::from_utf8_unchecked(&buf[..len]) });
}

/// Log a phase end
pub fn log_phase_end(phase: &str, detail: &str, duration_ns: u64) {
    log_event(phase, detail, duration_ns);
}

/// Start timing (returns current timestamp)
#[inline]
pub fn start() -> u64 {
    if is_enabled() {
        timestamp_ns()
    } else {
        0
    }
}

/// End timing and log
#[inline]
pub fn end_log(start: u64, phase: &str, detail: &str) {
    if start == 0 {
        return;
    }
    let end = timestamp_ns();
    let duration = end.saturating_sub(start);
    log_event(phase, detail, duration);
}

/// Format a perf line into buffer, return length
fn format_perf_line(buf: &mut [u8], rel_time: u64, phase: &str, detail: &str, duration: u64) -> usize {
    let mut pos = 0;

    // "PERF:"
    buf[pos..pos+5].copy_from_slice(b"PERF:");
    pos += 5;

    // relative time
    pos += write_u64(&mut buf[pos..], rel_time);
    buf[pos] = b':';
    pos += 1;

    // phase
    let phase_bytes = phase.as_bytes();
    let phase_len = phase_bytes.len().min(buf.len() - pos - 50);
    buf[pos..pos+phase_len].copy_from_slice(&phase_bytes[..phase_len]);
    pos += phase_len;
    buf[pos] = b':';
    pos += 1;

    // detail
    let detail_bytes = detail.as_bytes();
    let detail_len = detail_bytes.len().min(buf.len() - pos - 30);
    buf[pos..pos+detail_len].copy_from_slice(&detail_bytes[..detail_len]);
    pos += detail_len;
    buf[pos] = b':';
    pos += 1;

    // duration
    pos += write_u64(&mut buf[pos..], duration);
    buf[pos] = b'\n';
    pos += 1;

    pos
}

/// Format a start line
fn format_start_line(buf: &mut [u8], rel_time: u64, phase: &str, detail: &str) -> usize {
    let mut pos = 0;

    // "START:"
    buf[pos..pos+6].copy_from_slice(b"START:");
    pos += 6;

    // relative time
    pos += write_u64(&mut buf[pos..], rel_time);
    buf[pos] = b':';
    pos += 1;

    // phase
    let phase_bytes = phase.as_bytes();
    let phase_len = phase_bytes.len().min(buf.len() - pos - 50);
    buf[pos..pos+phase_len].copy_from_slice(&phase_bytes[..phase_len]);
    pos += phase_len;
    buf[pos] = b':';
    pos += 1;

    // detail
    let detail_bytes = detail.as_bytes();
    let detail_len = detail_bytes.len().min(buf.len() - pos - 10);
    buf[pos..pos+detail_len].copy_from_slice(&detail_bytes[..detail_len]);
    pos += detail_len;
    buf[pos] = b'\n';
    pos += 1;

    pos
}

/// Write u64 to buffer as decimal, return bytes written
fn write_u64(buf: &mut [u8], mut val: u64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut tmp = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }

    // Reverse into buf
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

/// Macro for timing a block of code
#[macro_export]
macro_rules! perf_timed {
    ($phase:expr, $detail:expr, $body:expr) => {{
        let _start = $crate::platform::redox::perf::start();
        let result = $body;
        $crate::platform::redox::perf::end_log(_start, $phase, $detail);
        result
    }};
}
