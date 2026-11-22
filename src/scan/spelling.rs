//! Ask the volume how it spells an existing path, without resolving links.

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[repr(C)]
struct Reply {
    length: u32,
    path: libc::attrreference_t,
    bytes: [u8; libc::PATH_MAX as usize],
}

pub(super) fn full_path(path: &Path) -> Option<PathBuf> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut query = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FULLPATH,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = Reply {
        length: 0,
        path: libc::attrreference_t {
            attr_dataoffset: 0,
            attr_length: 0,
        },
        bytes: [0; libc::PATH_MAX as usize],
    };
    // SAFETY: the path is NUL-terminated. The attribute list and reply are
    // live, aligned C structures, and the buffer size is the reply's size.
    let rc = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&raw mut query).cast(),
            (&raw mut reply).cast(),
            size_of::<Reply>(),
            libc::FSOPT_NOFOLLOW_ANY,
        )
    };
    if rc != 0 {
        return None;
    }
    // The offset is relative to the attribute reference, not to the reply.
    let start = usize::try_from(reply.path.attr_dataoffset)
        .ok()?
        .checked_sub(size_of::<libc::attrreference_t>())?;
    let end = start.checked_add(usize::try_from(reply.path.attr_length).ok()?)?;
    let used = usize::try_from(reply.length)
        .ok()?
        .checked_sub(std::mem::offset_of!(Reply, bytes))?;
    let bytes = reply.bytes.get(..used)?.get(start..end)?;
    let name = CStr::from_bytes_with_nul(bytes).ok()?;
    let spelled = Path::new(OsStr::from_bytes(name.to_bytes()));
    spelled.is_absolute().then(|| spelled.to_path_buf())
}
