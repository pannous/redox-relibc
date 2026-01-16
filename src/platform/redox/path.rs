use alloc::{
    borrow::ToOwned,
    boxed::Box,
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use core::{ffi::c_int, str};
use redox_rt::signal::tmp_disable_signals;
use syscall::{data::Stat, error::*, flag::*};

use super::{FdGuard, Pal, Sys, libcscheme};
use crate::{
    error::Errno,
    fs::File,
    header::{fcntl, limits, sys_file},
    out::Out,
    sync::Mutex,
};

pub use redox_path::{RedoxPath, canonicalize_using_cwd};

// TODO: Define in syscall
const PATH_MAX: usize = 4096;

// POSIX states chdir is both thread-safe and signal-safe. Thus we need to synchronize access to CWD, but at the
// same time forbid signal handlers from running in the meantime, to avoid reentrant deadlock.
pub fn chdir(path: &str) -> Result<()> {
    let _siglock = tmp_disable_signals();
    let mut cwd_guard = CWD.lock();

    // Use open_with_cwd to follow symlinks (handles EXDEV for cross-scheme symlinks)
    let fd = open_with_cwd(cwd_guard.as_deref(), path, O_STAT | O_CLOEXEC)?;

    // Get the final resolved path from fpath
    let mut path_buf = [0u8; PATH_MAX];
    let path_len = syscall::fpath(fd, &mut path_buf).map_err(|e| {
        let _ = syscall::close(fd);
        e
    })?;

    let mut stat = Stat::default();
    if syscall::fstat(fd, &mut stat).is_err() || (stat.st_mode & MODE_TYPE) != MODE_DIR {
        let _ = syscall::close(fd);
        return Err(Error::new(ENOTDIR));
    }
    let _ = syscall::close(fd);

    // Extract canonical path from fpath result
    let resolved_path = core::str::from_utf8(&path_buf[..path_len])
        .map_err(|_| Error::new(ENOENT))?;

    // Convert fpath result to canonical user-visible path
    // fpath returns paths like "/schemename/path" but users expect "/scheme/schemename/path"
    let canon: String = if resolved_path.starts_with("/scheme/file/") || resolved_path == "/scheme/file" {
        // /scheme/file/path -> /path (default file scheme)
        let stripped = resolved_path.strip_prefix("/scheme/file").unwrap_or("/");
        if stripped.is_empty() { "/".to_string() } else { stripped.to_string() }
    } else if resolved_path.starts_with("/scheme/") {
        // Already in /scheme/name format
        resolved_path.to_string()
    } else if resolved_path.starts_with("/") && !resolved_path.starts_with("/scheme") {
        // fpath returned /schemename/path, convert to /scheme/schemename/path
        format!("/scheme{}", resolved_path)
    } else {
        resolved_path.to_string()
    };

    *cwd_guard = Some(canon.into_boxed_str());

    Ok(())
}

// getcwd is similarly both thread-safe and signal-safe.
pub fn getcwd(mut buf: Out<[u8]>) -> Option<usize> {
    let _siglock = tmp_disable_signals();
    let cwd_guard = CWD.lock();
    let cwd = cwd_guard.as_deref().unwrap_or("").as_bytes();

    let [mut before, mut after] = buf.split_at_checked(cwd.len())?;

    before.copy_from_slice(&cwd);
    after.zero();

    Some(cwd.len())
}

// TODO: How much of this logic should be in redox-path?
fn canonicalize_with_cwd_internal(cwd: Option<&str>, path: &str) -> Result<String> {
    let path = canonicalize_using_cwd(cwd, path).ok_or(Error::new(ENOENT))?;

    let standard_scheme = path == "/scheme" || path.starts_with("/scheme/");
    let legacy_scheme = path
        .split("/")
        .next()
        .map(|c| c.contains(":"))
        .unwrap_or(false);

    Ok(if standard_scheme || legacy_scheme {
        path
    } else {
        let mut result = format!("/scheme/file{}", path);

        // Trim trailing / to keep path canonical.
        if result.as_bytes().last() == Some(&b'/') {
            result.pop();
        }

        result
    })
}

pub fn canonicalize(path: &str) -> Result<String> {
    let _siglock = tmp_disable_signals();
    let cwd_guard = CWD.lock();
    canonicalize_with_cwd_internal(cwd_guard.as_deref(), path)
}

// TODO: arraystring?
static CWD: Mutex<Option<Box<str>>> = Mutex::new(None);

pub fn set_cwd_manual(cwd: Box<str>) {
    let _siglock = tmp_disable_signals();
    *CWD.lock() = Some(cwd);
}

pub fn clone_cwd() -> Option<Box<str>> {
    let _siglock = tmp_disable_signals();
    CWD.lock().clone()
}

// Internal helper for symlink-following open. Takes CWD as parameter to avoid deadlock when
// called from chdir (which already holds the CWD lock).
fn open_with_cwd(cwd: Option<&str>, path: &str, flags: usize) -> Result<usize> {
    // TODO: SYMLOOP_MAX
    const MAX_LEVEL: usize = 64;

    let mut resolve_buf = [0_u8; 4096];
    let mut current_path = canonicalize_with_cwd_internal(cwd, path)?;

    for _ in 0..MAX_LEVEL {
        let open_res = if current_path.starts_with(libcscheme::LIBC_SCHEME) {
            libcscheme::open(&current_path, flags)
        } else {
            syscall::open(&*current_path, flags)
        };

        match open_res {
            Ok(fd) => return Ok(fd),
            Err(error) if error == Error::new(EXDEV) => {
                // EXDEV means a cross-scheme symlink was encountered. It could be:
                // 1. The final component is a symlink (old behavior)
                // 2. An intermediate component is a cross-scheme symlink (new case)
                //
                // First try the old approach: open the full path with O_SYMLINK
                let resolve_flags = O_CLOEXEC | O_SYMLINK | O_RDONLY;
                match syscall::open(&*current_path, resolve_flags) {
                    Ok(fd) => {
                        // Final component is the symlink
                        let resolve_fd = FdGuard::new(fd);
                        let bytes_read = resolve_fd.read(&mut resolve_buf)?;
                        if bytes_read == resolve_buf.len() {
                            return Err(Error::new(ENAMETOOLONG));
                        }
                        current_path = core::str::from_utf8(&resolve_buf[..bytes_read])
                            .map_err(|_| Error::new(ENOENT))?
                            .to_string();
                    }
                    Err(_) => {
                        // Intermediate component is the cross-scheme symlink
                        // Find which component by walking the path
                        current_path = resolve_intermediate_symlink(&current_path, &mut resolve_buf)?;
                    }
                }
            }
            Err(other_error) => return Err(other_error),
        }
    }
    Err(Error::new(ELOOP))
}

/// Find and resolve an intermediate cross-scheme symlink in the path.
/// Returns the path with the symlink target substituted.
fn resolve_intermediate_symlink(path: &str, buf: &mut [u8]) -> Result<String> {
    // Parse path: /scheme/name/a/b/c -> scheme=name, components=[a,b,c]
    let path = path.strip_prefix("/scheme/").ok_or(Error::new(EINVAL))?;
    let (scheme_name, ref_path) = path.split_once('/').ok_or(Error::new(EINVAL))?;

    let scheme_prefix = format!("/scheme/{}", scheme_name);
    let components: Vec<&str> = ref_path.split('/').filter(|s| !s.is_empty()).collect();

    // Try opening progressively longer prefixes to find the cross-scheme symlink
    let mut good_prefix = scheme_prefix.clone();

    for (i, component) in components.iter().enumerate() {
        let test_path = format!("{}/{}", good_prefix, component);

        // Try to stat this path component
        match syscall::open(&test_path, O_CLOEXEC | O_STAT) {
            Ok(fd) => {
                let _ = syscall::close(fd);
                good_prefix = test_path;
            }
            Err(e) if e == Error::new(EXDEV) => {
                // Found the cross-scheme symlink component
                // Open it with O_SYMLINK to read the target
                let resolve_flags = O_CLOEXEC | O_SYMLINK | O_RDONLY;
                let fd = syscall::open(&test_path, resolve_flags)?;
                let resolve_fd = FdGuard::new(fd);
                let bytes_read = resolve_fd.read(buf)?;
                if bytes_read == buf.len() {
                    return Err(Error::new(ENAMETOOLONG));
                }

                let symlink_target = core::str::from_utf8(&buf[..bytes_read])
                    .map_err(|_| Error::new(ENOENT))?;

                // Reconstruct the path: symlink_target + remaining components
                let remaining: Vec<&str> = components[i + 1..].to_vec();
                let new_path = if remaining.is_empty() {
                    symlink_target.to_string()
                } else {
                    format!("{}/{}", symlink_target.trim_end_matches('/'), remaining.join("/"))
                };

                return Ok(new_path);
            }
            Err(e) => return Err(e),
        }
    }

    // Shouldn't reach here if EXDEV was returned for the full path
    Err(Error::new(ENOENT))
}

// TODO: Move to redox-rt, or maybe part of it?
pub fn open(path: &str, flags: usize) -> Result<usize> {
    open_with_cwd(CWD.lock().as_deref(), path, flags)
}

pub fn dir_path_and_fd_path(socket_path: &str) -> Result<(String, String)> {
    let _siglock = tmp_disable_signals();
    let cwd_guard = CWD.lock();

    let full_path = canonicalize_with_cwd_internal(cwd_guard.as_deref(), socket_path)?;

    let redox_path = RedoxPath::from_absolute(&full_path).ok_or(Error::new(EINVAL))?;
    let (_, mut ref_path) = redox_path.as_parts().ok_or(Error::new(EINVAL))?;
    if ref_path.as_ref().is_empty() {
        return Err(Error::new(EINVAL));
    }
    if redox_path.is_default_scheme() {
        let dir_to_open = String::from(get_parent_path(&full_path).ok_or(Error::new(EINVAL))?);
        Ok((dir_to_open, ref_path.as_ref().to_string()))
    } else {
        let full_path = canonicalize_with_cwd_internal(cwd_guard.as_deref(), ref_path.as_ref())?;
        let redox_path = RedoxPath::from_absolute(&full_path).ok_or(Error::new(EINVAL))?;
        let (_, path) = redox_path.as_parts().ok_or(Error::new(EINVAL))?;
        let dir_to_open = String::from(get_parent_path(&full_path).ok_or(Error::new(EINVAL))?);
        Ok((dir_to_open, path.as_ref().to_string()))
    }
}

fn get_parent_path(path: &str) -> Option<&str> {
    path.rfind('/').and_then(|index| {
        if index == 0 {
            // Path is something like "/file.txt" or the root "/".
            // The parent is the root directory "/".
            Some("/")
        } else {
            // Path is something like "/a/b/c.txt".
            // Take the slice from the beginning up to the last '/'.
            Some(&path[..index])
        }
    })
}

pub struct FileLock(c_int);

impl FileLock {
    pub fn lock(fd: c_int, op: c_int) -> Result<Self> {
        if op & sys_file::LOCK_SH | sys_file::LOCK_EX == 0 {
            return Err(Error::new(EINVAL));
        }

        Sys::flock(fd, op)?;
        Ok(Self(fd))
    }

    pub fn unlock(self) -> Result<()> {
        Sys::flock(self.0, sys_file::LOCK_UN).map_err(Into::into)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = self.0;
        self.0 = -1;
        let _ = Sys::flock(self.0, sys_file::LOCK_UN);
    }
}
/// Resolve `path` under `dirfd`.
///
/// See [`openat2`] for more information.
pub(super) fn openat2_path(dirfd: c_int, path: &str, at_flags: c_int) -> Result<String, Errno> {
    // Ideally, the function calling this fn would check AT_EMPTY_PATH and just call fstat or
    // whatever with the fd.
    if path.is_empty() && at_flags & fcntl::AT_EMPTY_PATH != fcntl::AT_EMPTY_PATH {
        return Err(Errno(ENOENT));
    }

    // Absolute paths are passed without processing unless RESOLVE_BENEATH is used.
    // canonicalize_using_cwd checks that path is absolute so a third branch that does so here
    // isn't needed.
    if dirfd == fcntl::AT_FDCWD {
        // The special constant AT_FDCWD indicates that we should use the cwd.
        let mut buf = [0; limits::PATH_MAX];
        let len = getcwd(Out::from_mut(&mut buf)).ok_or(Errno(ENAMETOOLONG))?;
        // SAFETY: Redox's cwd is stored as a str.
        let cwd = unsafe { str::from_utf8_unchecked(&buf[..len]) };

        canonicalize_using_cwd(Some(cwd), path).ok_or(Errno(EBADF))
    } else {
        let mut buf = [0; limits::PATH_MAX];
        let len = Sys::fpath(dirfd, &mut buf)?;
        // SAFETY: fpath checks then copies valid UTF8.
        let dir = unsafe { str::from_utf8_unchecked(&buf[..len]) };

        canonicalize_using_cwd(Some(dir), path).ok_or(Errno(EBADF))
    }
}

/// Canonicalize and open `path` with respect to `dirfd`.
///
/// This unexported openat2 is similar to the Linux syscall but with a different interface. The
/// naming is mostly for convenience - it's not a drop in replacement for openat2.
///
/// # Arguments
/// * `dirfd` is a directory descriptor to which `path` is resolved.
/// * `path` is a relative or absolute path. Relative paths are resolved in relation to `dirfd`
/// while absolute paths skip `dirfd`.
/// * `at_flags` constrains how `path` is resolved.
/// * `oflags` are flags that are passed to open.
///
/// # Constants
/// `at_flags`:
/// * AT_EMPTY_PATH returns the path at `dirfd` itself if `path` is empty. If `path` is not
/// empty, it's resolved w.r.t `dirfd` like normal.
///
/// `dirfd`:
/// `AT_FDCWD` is a special constant for `dirfd` that resolves `path` under the current working
/// directory.
pub(super) fn openat2(
    dirfd: c_int,
    path: &str,
    at_flags: c_int,
    oflags: c_int,
) -> Result<File, Errno> {
    let path = openat2_path(dirfd, path, at_flags)?;
    let path = CString::new(path).map_err(|_| Errno(ENOENT))?;

    // Translate at flags into open flags; openat will do this on its own most likely.
    let oflags = if at_flags & fcntl::AT_SYMLINK_NOFOLLOW == fcntl::AT_SYMLINK_NOFOLLOW {
        fcntl::O_CLOEXEC | fcntl::O_NOFOLLOW | fcntl::O_PATH | fcntl::O_SYMLINK | oflags
    } else {
        fcntl::O_CLOEXEC | oflags
    };

    // TODO:
    // * Switch open to openat.
    File::open(path.as_c_str().into(), oflags)
}
