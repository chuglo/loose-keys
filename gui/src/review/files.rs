//! Access checks on open descriptors for the shared review store.

use crate::fsutil;
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

/// The folder `name` in `parent`, opened without following a link. With
/// `make`, it is made first if missing, private; without, None if missing.
pub(super) fn folder(parent: &File, name: &CStr, make: bool) -> Result<Option<File>, String> {
    // SAFETY: an open folder and a NUL-terminated name.
    if make
        && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err("Could not create the review list.".into());
    }
    // SAFETY: an open folder and a NUL-terminated name. O_NOFOLLOW refuses a
    // link, and O_DIRECTORY anything that is not a folder.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if !make && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err("Could not open the review list.".into())
        };
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

/// Whether anything is at `name` in `dir`. A link counts and is not followed.
pub(super) fn present(dir: &File, name: &CStr) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an open folder, a NUL-terminated name and room for one stat.
    unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        ) == 0
    }
}

/// Whether `name` in `dir` is a regular file of this user's that no one else
/// can read and that has no other name. A link is not followed.
pub(super) fn private_file(dir: &File, name: &CStr) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an open folder, a NUL-terminated name and room for one stat,
    // read only once fstatat has filled it.
    unsafe {
        if libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        ) != 0
        {
            return false;
        }
        let stat = stat.assume_init();
        stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == libc::geteuid()
            && stat.st_mode & 0o077 == 0
            && stat.st_nlink == 1
    }
}

/// The owner's mode alone does not rule out access granted by macOS ACLs.
pub(super) fn private_directory(dir: &File) -> bool {
    let Ok(meta) = dir.metadata() else {
        return false;
    };
    // SAFETY: geteuid has no preconditions.
    meta.uid() == unsafe { libc::geteuid() }
        && meta.mode() & 0o077 == 0
        && matches!(fsutil::has_access_grants(dir), Ok(false))
}

pub(super) fn open_file_at(dir: &File, name: &CStr) -> std::io::Result<Option<File>> {
    // SAFETY: live directory descriptor and NUL-terminated filename.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: openat returned a new owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
    let error = std::io::Error::last_os_error();
    match error.kind() {
        std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(error),
    }
}

pub(super) fn private_regular_file(file: &File, limit: u64) -> std::io::Result<bool> {
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let owner = unsafe { libc::geteuid() };
    Ok(meta.is_file()
        && meta.uid() == owner
        && meta.mode() & 0o077 == 0
        && meta.nlink() == 1
        && meta.len() <= limit
        && !fsutil::has_access_grants(file)?)
}
