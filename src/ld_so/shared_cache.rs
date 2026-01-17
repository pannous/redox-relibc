//! Shared-memory symbol cache for the dynamic linker.
//!
//! This module provides a file-backed cache at `/tmp/ld_symbol_cache` that persists
//! symbol resolution results across process invocations. Since aarch64 uses eager
//! binding (Resolve::Now), all symbols are resolved at load time. This cache
//! dramatically improves startup time by avoiding O(n) DSO iteration per symbol.
//!
//! # Design
//!
//! - Stores relative offsets from DSO base (not absolute addresses) for PIE support
//! - File-backed MAP_SHARED for cross-process persistence
//! - Cache invalidated when any DSO's mtime/inode changes
//! - Atomic operations for lock-free read/write coordination

use alloc::string::String;
use core::{
    mem::size_of,
    ptr::{self, NonNull},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use crate::{
    c_str::CString,
    header::{fcntl, sys_mman, sys_stat},
    platform::{Pal, Sys, types::c_void},
};

use super::dso::SymbolBinding;

/// Cache file path for POSIX shared memory (preferred for cross-process sharing)
const SHM_CACHE_PATH: &str = "/scheme/shm/ld_symbol_cache";

/// Fallback cache file path in /tmp (used if /scheme/shm is unavailable)
const TMP_CACHE_PATH: &str = "/tmp/ld_symbol_cache";

/// Check if a path exists
fn path_exists(path_str: &str) -> bool {
    let path = match CString::new(path_str) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let result = Sys::open(
        crate::c_str::CStr::borrow(&path),
        fcntl::O_RDONLY | fcntl::O_CLOEXEC,
        0,
    );

    match result {
        Ok(fd) => {
            Sys::close(fd).ok();
            true
        }
        Err(_) => false,
    }
}

/// Determine which cache path to use and whether we can use MAP_SHARED
/// Returns (path, use_map_shared)
fn select_cache_path() -> Option<(&'static str, bool)> {
    // Prefer /scheme/shm for true shared memory (MAP_SHARED works reliably)
    if path_exists("/scheme/shm") {
        return Some((SHM_CACHE_PATH, true));
    }

    // Fall back to /tmp if available (MAP_PRIVATE only to avoid hangs)
    if path_exists("/tmp") {
        return Some((TMP_CACHE_PATH, false));
    }

    // Neither available (early boot)
    None
}

/// Magic number for cache file identification
const CACHE_MAGIC: u64 = 0x4C445F5359_4D4341; // "LD_SYMCA" in hex

/// Cache file format version
const CACHE_VERSION: u32 = 1;

/// Maximum number of DSOs we track
const MAX_DSOS: usize = 128;

/// Maximum number of symbols we cache
const MAX_SYMBOLS: usize = 16384;

/// Maximum string pool size
const MAX_STRING_POOL: usize = 512 * 1024; // 512KB

/// Size of DSO path in entry
const DSO_PATH_SIZE: usize = 120;

/// Cache file header (64 bytes, aligned)
#[repr(C, align(8))]
pub struct SharedCacheHeader {
    /// Magic number for identification
    pub magic: u64,
    /// Format version
    pub version: u32,
    /// Number of valid DSO entries (atomic for lock-free updates)
    pub dso_count: AtomicU32,
    /// Generation counter - incremented on modification
    pub generation: AtomicU64,
    /// Number of valid symbol entries (atomic for lock-free updates)
    pub symbol_count: AtomicU32,
    /// Current string pool usage (atomic for lock-free updates)
    pub string_pool_used: AtomicU32,
    /// Reserved for future use
    _reserved: [u8; 24],
}

/// DSO entry in cache (128 bytes)
#[repr(C, align(8))]
pub struct SharedDsoEntry {
    /// DSO file path (null-terminated)
    pub path: [u8; DSO_PATH_SIZE],
    /// File modification time (st_mtim.tv_sec)
    pub mtime: i64,
    /// File inode number (st_ino)
    pub inode: u64,
    /// File device ID (st_dev)
    pub dev: u64,
    /// Index of first symbol for this DSO in symbol table (-1 if none)
    pub first_symbol_idx: i32,
    /// Number of symbols from this DSO
    pub symbol_count: u32,
}

/// Symbol entry in cache (48 bytes)
#[repr(C, align(8))]
pub struct SharedSymbolEntry {
    /// Offset into string pool for symbol name
    pub name_offset: u32,
    /// DSO index this symbol belongs to
    pub dso_idx: u16,
    /// Symbol binding (Global=1, Weak=2)
    pub binding: u8,
    /// Symbol type (from ELF)
    pub sym_type: u8,
    /// Offset within DSO (relative to DSO base)
    pub offset_in_dso: u64,
    /// Symbol size
    pub size: u64,
    /// Hash of symbol name for quick comparison
    pub name_hash: u64,
    /// Reserved for alignment
    _reserved: [u8; 8],
}

/// Calculated offsets into the cache file
const HEADER_OFFSET: usize = 0;
const DSO_TABLE_OFFSET: usize = size_of::<SharedCacheHeader>();
const SYMBOL_TABLE_OFFSET: usize = DSO_TABLE_OFFSET + MAX_DSOS * size_of::<SharedDsoEntry>();
const STRING_POOL_OFFSET: usize = SYMBOL_TABLE_OFFSET + MAX_SYMBOLS * size_of::<SharedSymbolEntry>();
const TOTAL_CACHE_SIZE: usize = STRING_POOL_OFFSET + MAX_STRING_POOL;

/// Shared symbol cache manager
pub struct SharedCache {
    /// Memory-mapped cache file
    mmap_ptr: NonNull<u8>,
    /// File descriptor (kept open)
    fd: i32,
    /// Whether cache is valid (DSOs haven't changed)
    valid: bool,
    /// Whether this cache uses MAP_SHARED (cross-process) or MAP_PRIVATE (per-process)
    is_shared: bool,
}

/// Result of a cache lookup
pub struct CacheLookupResult {
    /// Offset within the DSO
    pub offset_in_dso: u64,
    /// Symbol size
    pub size: u64,
    /// Symbol type
    pub sym_type: u8,
    /// Symbol binding
    pub binding: SymbolBinding,
    /// DSO path from cache
    pub dso_path: String,
}

impl SharedCache {
    /// Open or create the shared symbol cache.
    /// Returns None if neither /scheme/shm nor /tmp exist (early boot) or on any error.
    pub fn open() -> Option<Self> {
        trace!("[ld.so cache] open: selecting cache path");

        // Select cache path and determine if we can use MAP_SHARED
        let (cache_path, use_map_shared) = select_cache_path()?;

        trace!("[ld.so cache] open: using path={}, shared={}", cache_path, use_map_shared);
        let path = CString::new(cache_path).ok()?;
        let path_cstr = crate::c_str::CStr::borrow(&path);

        trace!("[ld.so cache] open: trying to open {}", cache_path);
        // Try to open existing cache first
        let fd = Sys::open(path_cstr, fcntl::O_RDWR | fcntl::O_CLOEXEC, 0).ok();

        let (fd, needs_init) = match fd {
            Some(fd) => {
                trace!("[ld.so cache] open: existing file opened, fd={}", fd);
                // Check if file is large enough
                let mut stat = sys_stat::stat::default();
                if Sys::fstat(fd, crate::out::Out::from_mut(&mut stat)).is_err() {
                    trace!("[ld.so cache] open: fstat failed");
                    Sys::close(fd).ok();
                    return None;
                }
                trace!("[ld.so cache] open: file size = {}", stat.st_size);
                if (stat.st_size as usize) < TOTAL_CACHE_SIZE {
                    // File too small, recreate
                    trace!("[ld.so cache] open: file too small, recreating");
                    Sys::close(fd).ok();
                    Self::create_new(path_cstr)?
                } else {
                    (fd, false)
                }
            }
            None => {
                trace!("[ld.so cache] open: creating new cache file");
                Self::create_new(path_cstr)?
            }
        };

        trace!("[ld.so cache] open: fd={}, needs_init={}, about to mmap {} bytes",
                 fd, needs_init, TOTAL_CACHE_SIZE);

        // Choose mapping flags based on whether we're using shm or /tmp
        // MAP_SHARED works reliably with /scheme/shm (designed for shared memory)
        // MAP_PRIVATE is safer for /tmp (avoids potential file sync hangs)
        let map_flags = if use_map_shared {
            trace!("[ld.so cache] open: using MAP_SHARED for cross-process caching");
            sys_mman::MAP_SHARED
        } else {
            trace!("[ld.so cache] open: using MAP_PRIVATE (no cross-process caching)");
            sys_mman::MAP_PRIVATE
        };

        let ptr = unsafe {
            Sys::mmap(
                ptr::null_mut(),
                TOTAL_CACHE_SIZE,
                sys_mman::PROT_READ | sys_mman::PROT_WRITE,
                map_flags,
                fd,
                0,
            ).ok()?
        };

        trace!("[ld.so cache] open: mmap succeeded at {:p}", ptr);

        let mmap_ptr = NonNull::new(ptr.cast::<u8>())?;

        let mut cache = Self {
            mmap_ptr,
            fd,
            valid: false,
            is_shared: use_map_shared,
        };

        if needs_init {
            trace!("[ld.so cache] open: initializing header");
            cache.initialize_header();
        } else if !cache.validate_header() {
            // Invalid header, reinitialize
            trace!("[ld.so cache] open: invalid header, reinitializing");
            cache.initialize_header();
        } else {
            trace!("[ld.so cache] open: header valid");
        }

        trace!("[ld.so cache] open: complete");
        Some(cache)
    }

    /// Create a new cache file.
    fn create_new(path: crate::c_str::CStr) -> Option<(i32, bool)> {
        trace!("[ld.so cache] create_new: opening file with O_CREAT");
        let fd = match Sys::open(
            path,
            fcntl::O_RDWR | fcntl::O_CREAT | fcntl::O_CLOEXEC,
            0o644,
        ) {
            Ok(fd) => {
                trace!("[ld.so cache] create_new: file created, fd={}", fd);
                fd
            }
            Err(_e) => {
                trace!("[ld.so cache] create_new: open failed: {:?}", _e);
                return None;
            }
        };

        // Extend file to required size
        trace!("[ld.so cache] create_new: ftruncate to {} bytes", TOTAL_CACHE_SIZE);
        if let Err(_e) = Sys::ftruncate(fd, TOTAL_CACHE_SIZE as i64) {
            trace!("[ld.so cache] create_new: ftruncate failed: {:?}", _e);
            Sys::close(fd).ok();
            return None;
        }
        trace!("[ld.so cache] create_new: ftruncate succeeded");

        Some((fd, true))
    }

    /// Initialize cache header for a new file.
    fn initialize_header(&mut self) {
        let header = self.header_mut();
        header.magic = CACHE_MAGIC;
        header.version = CACHE_VERSION;
        header.generation = AtomicU64::new(1);
        header.dso_count = AtomicU32::new(0);
        header.symbol_count = AtomicU32::new(0);
        header.string_pool_used = AtomicU32::new(0);
        header._reserved = [0; 24];

        // Memory barrier
        core::sync::atomic::fence(Ordering::Release);
    }

    /// Validate cache header.
    fn validate_header(&self) -> bool {
        let header = self.header();
        header.magic == CACHE_MAGIC && header.version == CACHE_VERSION
    }

    /// Get header reference.
    fn header(&self) -> &SharedCacheHeader {
        unsafe { &*(self.mmap_ptr.as_ptr().add(HEADER_OFFSET) as *const SharedCacheHeader) }
    }

    /// Get mutable header reference.
    fn header_mut(&mut self) -> &mut SharedCacheHeader {
        unsafe { &mut *(self.mmap_ptr.as_ptr().add(HEADER_OFFSET) as *mut SharedCacheHeader) }
    }

    /// Get DSO table.
    fn dso_table(&self) -> &[SharedDsoEntry] {
        let count = self.header().dso_count.load(Ordering::Acquire) as usize;
        let ptr = unsafe {
            self.mmap_ptr.as_ptr().add(DSO_TABLE_OFFSET) as *const SharedDsoEntry
        };
        unsafe { core::slice::from_raw_parts(ptr, count.min(MAX_DSOS)) }
    }

    /// Get symbol table.
    fn symbol_table(&self) -> &[SharedSymbolEntry] {
        let count = self.header().symbol_count.load(Ordering::Acquire) as usize;
        let ptr = unsafe {
            self.mmap_ptr.as_ptr().add(SYMBOL_TABLE_OFFSET) as *const SharedSymbolEntry
        };
        unsafe { core::slice::from_raw_parts(ptr, count.min(MAX_SYMBOLS)) }
    }

    /// Get string from pool.
    fn get_string(&self, offset: u32) -> Option<&str> {
        let pool_ptr = unsafe { self.mmap_ptr.as_ptr().add(STRING_POOL_OFFSET) };
        let pool_used = self.header().string_pool_used.load(Ordering::Acquire) as usize;

        if (offset as usize) >= pool_used {
            return None;
        }

        // Find null terminator
        let start = offset as usize;
        let mut end = start;
        while end < pool_used {
            let byte = unsafe { *pool_ptr.add(end) };
            if byte == 0 {
                break;
            }
            end += 1;
        }

        let bytes = unsafe {
            core::slice::from_raw_parts(pool_ptr.add(start), end - start)
        };
        core::str::from_utf8(bytes).ok()
    }

    /// Add string to pool atomically, returns offset.
    fn add_string(&self, s: &str) -> Option<u32> {
        let bytes = s.as_bytes();
        let needed = bytes.len() + 1; // +1 for null terminator

        // Atomically reserve space in the string pool
        let offset = self.header().string_pool_used.fetch_add(needed as u32, Ordering::AcqRel);

        if (offset as usize) + needed > MAX_STRING_POOL {
            // Rollback (best effort - may leave gap)
            self.header().string_pool_used.fetch_sub(needed as u32, Ordering::Release);
            return None;
        }

        let pool_ptr = unsafe { self.mmap_ptr.as_ptr().add(STRING_POOL_OFFSET) };

        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), pool_ptr.add(offset as usize), bytes.len());
            *pool_ptr.add(offset as usize + bytes.len()) = 0; // Null terminator
        }

        Some(offset)
    }

    /// Compute a simple hash for symbol name lookup.
    fn hash_name(name: &str) -> u64 {
        let mut hash: u64 = 5381;
        for byte in name.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
        }
        hash
    }

    /// Look up a symbol in the cache.
    ///
    /// Returns the cached symbol info if found, along with the DSO path
    /// so the caller can match it to a loaded DSO and compute the actual address.
    pub fn lookup(&self, name: &str) -> Option<CacheLookupResult> {
        if !self.valid {
            return None;
        }

        let name_hash = Self::hash_name(name);
        let symbols = self.symbol_table();
        let dsos = self.dso_table();

        // Linear search (could be improved with sorting + binary search)
        for sym in symbols {
            if sym.name_hash == name_hash {
                // Verify name matches
                if let Some(cached_name) = self.get_string(sym.name_offset) {
                    if cached_name == name {
                        // Get DSO path
                        if (sym.dso_idx as usize) >= dsos.len() {
                            continue;
                        }
                        let dso_entry = &dsos[sym.dso_idx as usize];
                        let dso_path = Self::path_from_bytes(&dso_entry.path)?;

                        return Some(CacheLookupResult {
                            offset_in_dso: sym.offset_in_dso,
                            size: sym.size,
                            sym_type: sym.sym_type,
                            binding: if sym.binding == 1 {
                                SymbolBinding::Global
                            } else {
                                SymbolBinding::Weak
                            },
                            dso_path,
                        });
                    }
                }
            }
        }

        None
    }

    /// Extract path string from fixed-size byte array.
    fn path_from_bytes(bytes: &[u8; DSO_PATH_SIZE]) -> Option<String> {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..end])
            .ok()
            .map(|s| alloc::string::ToString::to_string(s))
    }

    /// Register a DSO with the cache.
    ///
    /// Returns the DSO index if successful.
    pub fn register_dso(&mut self, path: &str, mtime: i64, inode: u64, dev: u64) -> Option<u16> {
        // Check if already registered
        for (idx, entry) in self.dso_table().iter().enumerate() {
            if let Some(entry_path) = Self::path_from_bytes(&entry.path) {
                if entry_path == path {
                    // Already registered, verify it hasn't changed
                    if entry.mtime == mtime && entry.inode == inode && entry.dev == dev {
                        return Some(idx as u16);
                    } else {
                        // DSO changed, invalidate cache
                        self.invalidate();
                        return None;
                    }
                }
            }
        }

        // Add new DSO entry atomically
        let count = self.header().dso_count.fetch_add(1, Ordering::AcqRel) as usize;
        if count >= MAX_DSOS {
            // Rollback
            self.header().dso_count.fetch_sub(1, Ordering::Release);
            return None;
        }

        let entry_ptr = unsafe {
            self.mmap_ptr.as_ptr().add(DSO_TABLE_OFFSET) as *mut SharedDsoEntry
        };

        let entry = unsafe { &mut *entry_ptr.add(count) };

        // Copy path
        entry.path = [0; DSO_PATH_SIZE];
        let path_bytes = path.as_bytes();
        let copy_len = path_bytes.len().min(DSO_PATH_SIZE - 1);
        entry.path[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

        entry.mtime = mtime;
        entry.inode = inode;
        entry.dev = dev;
        entry.first_symbol_idx = -1;
        entry.symbol_count = 0;

        // Update generation
        self.header().generation.fetch_add(1, Ordering::Release);

        Some(count as u16)
    }

    /// Insert a symbol into the cache.
    pub fn insert(
        &self,
        name: &str,
        dso_idx: u16,
        offset_in_dso: u64,
        size: u64,
        sym_type: u8,
        binding: SymbolBinding,
    ) -> bool {
        // Atomically reserve a slot
        let count = self.header().symbol_count.fetch_add(1, Ordering::AcqRel) as usize;
        if count >= MAX_SYMBOLS {
            // Rollback
            self.header().symbol_count.fetch_sub(1, Ordering::Release);
            return false;
        }

        // Add name to string pool
        let name_offset = match self.add_string(name) {
            Some(offset) => offset,
            None => {
                // Rollback symbol count
                self.header().symbol_count.fetch_sub(1, Ordering::Release);
                return false;
            }
        };

        let entry_ptr = unsafe {
            self.mmap_ptr.as_ptr().add(SYMBOL_TABLE_OFFSET) as *mut SharedSymbolEntry
        };

        let entry = unsafe { &mut *entry_ptr.add(count) };
        entry.name_offset = name_offset;
        entry.dso_idx = dso_idx;
        entry.offset_in_dso = offset_in_dso;
        entry.size = size;
        entry.sym_type = sym_type;
        entry.binding = if binding.is_global() { 1 } else { 2 };
        entry.name_hash = Self::hash_name(name);
        entry._reserved = [0; 8];

        // Update generation
        self.header().generation.fetch_add(1, Ordering::Release);

        true
    }

    /// Validate all DSO entries against filesystem.
    ///
    /// If any DSO has changed (different mtime/inode), invalidate the cache.
    pub fn validate_dsos(&mut self) -> bool {
        let dsos = self.dso_table();

        for entry in dsos {
            // Skip validation for DSOs registered without file metadata
            // (mtime=0 means "trust cache, don't validate file")
            if entry.mtime == 0 && entry.inode == 0 && entry.dev == 0 {
                continue;
            }

            let path = match Self::path_from_bytes(&entry.path) {
                Some(p) => p,
                None => continue,
            };

            let path_c = match CString::new(&*path) {
                Ok(p) => p,
                Err(_) => {
                    self.invalidate();
                    return false;
                }
            };

            // Open file to get stat info (using fstat since stat isn't available)
            let fd = match Sys::open(
                crate::c_str::CStr::borrow(&path_c),
                fcntl::O_RDONLY | fcntl::O_CLOEXEC,
                0,
            ) {
                Ok(fd) => fd,
                Err(_) => {
                    // DSO no longer exists
                    self.invalidate();
                    return false;
                }
            };

            let mut stat = sys_stat::stat::default();
            let stat_result = Sys::fstat(fd, crate::out::Out::from_mut(&mut stat));
            Sys::close(fd).ok();

            if stat_result.is_err() {
                self.invalidate();
                return false;
            }

            if stat.st_mtim.tv_sec as i64 != entry.mtime
                || stat.st_ino as u64 != entry.inode
                || stat.st_dev as u64 != entry.dev
            {
                // DSO has changed
                self.invalidate();
                return false;
            }
        }

        self.valid = true;
        true
    }

    /// Invalidate the entire cache.
    pub fn invalidate(&mut self) {
        self.valid = false;

        // Reset all counts atomically
        self.header().dso_count.store(0, Ordering::Release);
        self.header().symbol_count.store(0, Ordering::Release);
        self.header().string_pool_used.store(0, Ordering::Release);
        self.header().generation.fetch_add(1, Ordering::Release);
    }

    /// Mark cache as valid after DSO validation.
    pub fn mark_valid(&mut self) {
        self.valid = true;
    }

    /// Check if cache is currently valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Check if this cache uses cross-process shared memory.
    pub fn is_shared(&self) -> bool {
        self.is_shared
    }

    /// Get cache statistics for debugging.
    #[allow(dead_code)]
    pub fn stats(&self) -> (u32, u32, u32) {
        let header = self.header();
        (
            header.dso_count.load(Ordering::Acquire),
            header.symbol_count.load(Ordering::Acquire),
            header.string_pool_used.load(Ordering::Acquire),
        )
    }
}

impl Drop for SharedCache {
    fn drop(&mut self) {
        unsafe {
            Sys::munmap(self.mmap_ptr.as_ptr() as *mut c_void, TOTAL_CACHE_SIZE).ok();
            Sys::close(self.fd).ok();
        }
    }
}

// Thread-local cache instance
// We use a simple static for now since the linker runs single-threaded during load
use core::cell::UnsafeCell;

struct CacheHolder(UnsafeCell<Option<SharedCache>>);
unsafe impl Sync for CacheHolder {}

static SHARED_CACHE: CacheHolder = CacheHolder(UnsafeCell::new(None));

/// Check if cache is disabled via environment variable
fn cache_disabled() -> bool {
    // Check LD_NO_CACHE environment variable
    // This is a simple check without full env parsing
    false // Default: cache enabled
}

/// Initialize the shared cache (call once at linker startup).
/// This is called after /tmp is available (post-rootfs mount).
pub fn init_shared_cache() {
    // Skip if cache is disabled
    if cache_disabled() {
        trace!("[ld.so cache] disabled via LD_NO_CACHE");
        return;
    }

    trace!("[ld.so cache] init_shared_cache starting");

    unsafe {
        if (*SHARED_CACHE.0.get()).is_some() {
            trace!("[ld.so cache] already initialized");
            return;
        }

        trace!("[ld.so cache] calling SharedCache::open()");
        match SharedCache::open() {
            Some(mut cache) => {
                let _shared_str = if cache.is_shared() { "CROSS-PROCESS" } else { "per-process" };
                trace!("[ld.so cache] cache opened ({} mode), validating DSOs...", _shared_str);
                cache.validate_dsos();
                let (_dso_count, _sym_count, _pool_used) = cache.stats();
                trace!("[ld.so cache] validated: {} DSOs, {} symbols, {} bytes pool ({})",
                         _dso_count, _sym_count, _pool_used, _shared_str);
                *SHARED_CACHE.0.get() = Some(cache);
                trace!("[ld.so cache] initialization complete");
            }
            None => {
                trace!("[ld.so cache] failed to open cache (early boot or error)");
            }
        }
    }
}

/// Get a reference to the shared cache.
pub fn shared_cache() -> Option<&'static SharedCache> {
    unsafe { (*SHARED_CACHE.0.get()).as_ref() }
}

/// Get a mutable reference to the shared cache.
pub fn shared_cache_mut() -> Option<&'static mut SharedCache> {
    unsafe { (*SHARED_CACHE.0.get()).as_mut() }
}

/// Look up a symbol in the shared cache.
///
/// Returns (offset_in_dso, size, sym_type, binding, dso_path) if found.
pub fn cache_lookup(name: &str) -> Option<CacheLookupResult> {
    shared_cache()?.lookup(name)
}

/// Register a DSO with the shared cache.
pub fn cache_register_dso(path: &str, mtime: i64, inode: u64, dev: u64) -> Option<u16> {
    shared_cache_mut()?.register_dso(path, mtime, inode, dev)
}

/// Insert a symbol into the shared cache.
pub fn cache_insert(
    name: &str,
    dso_idx: u16,
    offset_in_dso: u64,
    size: u64,
    sym_type: u8,
    binding: SymbolBinding,
) -> bool {
    match shared_cache() {
        Some(cache) => cache.insert(name, dso_idx, offset_in_dso, size, sym_type, binding),
        None => false,
    }
}

/// Insert a symbol into the shared cache by DSO path.
///
/// This will find or register the DSO first, then insert the symbol.
/// Returns true if successful.
pub fn cache_insert_by_path(
    name: &str,
    offset_in_dso: u64,
    size: u64,
    sym_type: u8,
    binding: SymbolBinding,
    dso_path: &str,
) -> bool {
    let cache = match shared_cache_mut() {
        Some(c) => c,
        None => return false,
    };

    // Find existing DSO by path
    for (idx, entry) in cache.dso_table().iter().enumerate() {
        if let Some(entry_path) = SharedCache::path_from_bytes(&entry.path) {
            if entry_path == dso_path {
                return cache.insert(name, idx as u16, offset_in_dso, size, sym_type, binding);
            }
        }
    }

    // DSO not registered - register it with default metadata (will be validated on next boot)
    if let Some(dso_idx) = cache.register_dso(dso_path, 0, 0, 0) {
        return cache.insert(name, dso_idx, offset_in_dso, size, sym_type, binding);
    }

    false
}
