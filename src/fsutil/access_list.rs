//! Descriptor-bound checks for macOS access control lists.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;

// macOS declares these in sys/acl.h.
extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_permset(entry: *mut libc::c_void, perms: *mut *mut libc::c_void) -> libc::c_int;
    fn acl_get_perm_np(perms: *mut libc::c_void, perm: libc::c_int) -> libc::c_int;
    fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
}

pub(super) fn has_access_list(file: &File) -> io::Result<bool> {
    any_entry(file, |_| Ok(true))
}

/// A deny entry only takes rights away. An allow entry cannot be verified
/// as owner-only from the descriptor's POSIX ownership alone.
pub fn has_access_grants(file: &File) -> io::Result<bool> {
    any_entry(file, Entry::allows)
}

/// Whether a folder's ACL grants anyone rights to change the folder's
/// entries, ACL or owner. Used independently of the review store's policy.
pub(super) fn lets_others_change(dir: &File) -> io::Result<bool> {
    // ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD,
    // ACL_WRITE_SECURITY and ACL_CHANGE_OWNER.
    const CHANGES: [libc::c_int; 5] = [1 << 2, 1 << 5, 1 << 6, 1 << 12, 1 << 13];
    any_entry(dir, |entry| {
        if !entry.allows()? {
            return Ok(false);
        }
        let mut perms = std::ptr::null_mut();
        // SAFETY: `entry` belongs to the live ACL and `perms` is writable.
        if unsafe { acl_get_permset(entry.0, &mut perms) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for perm in CHANGES {
            // SAFETY: `perms` came from a live entry, and `perm` is a
            // permission value from sys/acl.h.
            match unsafe { acl_get_perm_np(perms, perm) } {
                0 => {}
                1 => return Ok(true),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        Ok(false)
    })
}

struct Entry(*mut libc::c_void);

impl Entry {
    fn allows(&self) -> io::Result<bool> {
        let mut tag = 0;
        // SAFETY: the entry belongs to a live ACL and `tag` is writable.
        if unsafe { acl_get_tag_type(self.0, &mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match tag {
            ACL_EXTENDED_ALLOW => Ok(true),
            ACL_EXTENDED_DENY => Ok(false),
            _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
}

fn any_entry(file: &File, mut matches: impl FnMut(&Entry) -> io::Result<bool>) -> io::Result<bool> {
    // SAFETY: live descriptor and a valid list type. The resulting list
    // belongs to this call and is released before returning.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(error),
        };
    }
    let mut which = ACL_FIRST_ENTRY;
    let found = loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is live and `entry` is writable. The returned
        // entry is used only in this iteration while the list is live.
        if unsafe { acl_get_entry(acl, which, &mut entry) } != 0 {
            let error = io::Error::last_os_error();
            // On a valid list these indices are out of range only once
            // the list has no further entries.
            break match error.raw_os_error() {
                Some(libc::EINVAL) => Ok(false),
                _ => Err(error),
            };
        }
        which = ACL_NEXT_ENTRY;
        match matches(&Entry(entry)) {
            Ok(false) => {}
            result => break result,
        }
    };
    // SAFETY: no entry outlives the loop and the list is freed once.
    unsafe { acl_free(acl) };
    found
}
