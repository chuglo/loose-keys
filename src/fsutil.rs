//! Careful file access: never follow symlinks, never block on special files,
//! never trigger cloud downloads, and read only the first bytes we need.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Why something in scope could not be checked (matches the report schema).
pub type Gap = &'static str;

pub struct Head {
    pub bytes: Vec<u8>,
    /// Group/other read mode bits only, not effective access (ancestors/ACLs).
    pub shared: bool,
}

/// The flag macOS sets on a file whose contents are in the cloud only.
const SF_DATALESS: u32 = 0x4000_0000;

/// The most entries `list_dir` gives of one folder.
pub const FOLDER_ENTRIES: usize = 10_000;

fn is_dataless(meta: &fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt as MacExt;
    meta.st_flags() & SF_DATALESS != 0
}

fn gap(e: &io::Error) -> Gap {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "permission-denied",
        _ => "unreadable",
    }
}

/// Read at most `max` bytes from a regular file.
/// Ok(None): absent, a symlink, or not a regular file (skipped by design).
/// Err(gap): in scope but could not be checked.
pub fn read_head(path: &Path, max: u64) -> Result<Option<Head>, Gap> {
    open_path(path, false)?.map(|f| head_of(f, max)).transpose()
}

/// As `read_head`, for an entry of a folder `list_dir` opened: only the
/// entry is checked, because the folder's handle was opened without
/// following links. Its listing came from the same handle.
pub fn read_head_in(dir: &File, name: &OsStr, max: u64) -> Result<Option<Head>, Gap> {
    open_at(dir, name, false)?
        .map(|f| head_of(f, max))
        .transpose()
}

fn head_of(file: File, max: u64) -> Result<Head, Gap> {
    let meta = file.metadata().map_err(|e| gap(&e))?;
    let mut bytes = with_room(meta.len(), max);
    file.take(max)
        .read_to_end(&mut bytes)
        .map_err(|e| gap(&e))?;
    Ok(Head {
        bytes,
        shared: meta.mode() & 0o044 != 0,
    })
}

/// An empty buffer with room for a file that says it holds `len` bytes, read
/// up to `max`, so that one read usually fills it: grown from nothing, it
/// takes a read for each doubling. `max` caps the room, whatever `len` says.
fn with_room(len: u64, max: u64) -> Vec<u8> {
    Vec::with_capacity(usize::try_from(len.min(max)).unwrap_or(0))
}

/// Open a regular file for reading in pieces, with its size and whether
/// group/other read mode bits are set. Ok(None) as for `read_head`.
pub fn open_regular(path: &Path) -> Result<Option<(File, u64, bool)>, Gap> {
    let Some(file) = open_path(path, false)? else {
        return Ok(None);
    };
    let meta = file.metadata().map_err(|e| gap(&e))?;
    Ok(Some((file, meta.len(), meta.mode() & 0o044 != 0)))
}

/// Read a complete small file, checking size on the same handle used to read.
/// Never accept truncated input or read more than `max` bytes.
pub fn read_config(path: &Path, max: u64) -> Result<Option<Head>, Gap> {
    open_path(path, false)?
        .map(|f| config_of(f, max))
        .transpose()
}

/// As `read_config`, for an entry of a folder `list_dir` opened, as
/// `read_head_in` reads one.
pub fn read_config_in(dir: &File, name: &OsStr, max: u64) -> Result<Option<Head>, Gap> {
    open_at(dir, name, false)?
        .map(|f| config_of(f, max))
        .transpose()
}

fn config_of(mut file: File, max: u64) -> Result<Head, Gap> {
    let before = file.metadata().map_err(|e| gap(&e))?;
    if before.len() > max {
        return Err("too-large");
    }
    let mut bytes = with_room(before.len(), max);
    (&mut file)
        .take(max)
        .read_to_end(&mut bytes)
        .map_err(|e| gap(&e))?;
    let after = file.metadata().map_err(|e| gap(&e))?;
    if after.len() > max {
        return Err("too-large");
    }
    if before.len() != after.len() || bytes.len() as u64 != after.len() {
        return Err("unreadable");
    }
    Ok(Head {
        bytes,
        shared: before.mode() & 0o044 != 0,
    })
}

/// Open each component relative to an already-open directory, never following
/// links (including ancestors). Check cloud flags before open and before reads.
fn open_path(path: &Path, directory: bool) -> Result<Option<File>, Gap> {
    if !path.is_absolute() {
        return Err("unreadable");
    }
    let mut file = File::open("/").map_err(|e| gap(&e))?;
    let parts: Vec<_> = path
        .components()
        .filter(|c| *c != Component::RootDir && *c != Component::CurDir)
        .collect();
    for (i, component) in parts.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err("unreadable");
        };
        let want_dir = directory || i + 1 < parts.len();
        let Some(next) = open_at(&file, name, want_dir)? else {
            return Ok(None);
        };
        file = next;
    }
    Ok(Some(file))
}

/// Open one entry of an open directory: a folder if `want_dir`, else a
/// regular file. Ok(None) for a link, another kind of file or nothing there.
fn open_at(dir: &File, name: &OsStr, want_dir: bool) -> Result<Option<File>, Gap> {
    let name = CString::new(name.as_bytes()).map_err(|_| "unreadable")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: live parent descriptor, NUL-terminated name and writable stat.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(gap(&e))
        };
    }
    // SAFETY: fstatat reported success, so it filled the stat.
    let stat = unsafe { stat.assume_init() };
    let kind = stat.st_mode & libc::S_IFMT;
    if kind
        != if want_dir {
            libc::S_IFDIR
        } else {
            libc::S_IFREG
        }
    {
        return Ok(None);
    }
    if stat.st_flags & SF_DATALESS != 0 {
        return Err("cloud-only-file");
    }
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if want_dir { libc::O_DIRECTORY } else { 0 };
    // SAFETY: live parent descriptor and NUL-terminated name.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return if matches!(
            e.raw_os_error(),
            Some(libc::ELOOP | libc::ENOENT | libc::ENOTDIR)
        ) {
            Ok(None)
        } else {
            Err(gap(&e))
        };
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|e| gap(&e))?;
    if (want_dir && !meta.is_dir()) || (!want_dir && !meta.is_file()) {
        return Ok(None);
    }
    if is_dataless(&meta) {
        return Err("cloud-only-file");
    }
    Ok(Some(file))
}

/// Where a path under `home` really is, when it or a folder above it is a
/// symbolic link. None: no link on the way, or nothing there, or a folder on
/// the way that cannot be looked in, which reading the path as it is named,
/// or asking with `presence` whether it is there, then reports. Some(Ok): the
/// real location, which is inside `home` and is then opened without following
/// links like any other path. Some(Err): the link is not followed, because it
/// leads outside `home` ("symlink") or cannot be resolved, as when it loops
/// or passes through a folder that cannot be opened (the gap that says why).
pub fn through_links(path: &Path, home: &Path) -> Option<Result<PathBuf, Gap>> {
    let mut current = home.to_path_buf();
    for part in path.strip_prefix(home).ok()?.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return match fs::canonicalize(path) {
                    Ok(real) if real.starts_with(home) => Some(Ok(real)),
                    Ok(_) => Some(Err("symlink")),
                    // Nothing there, or below a file where nothing can be.
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                        None
                    }
                    Err(e) => Some(Err(gap(&e))),
                };
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// The link at `path`, or on the way to it below `home`, that leads nowhere,
/// as to a drive that is not connected: what it stands for can be told
/// neither to be there nor to be gone. `through_links` gives None for such a
/// path, as for one with nothing at its end. Nothing is opened.
pub fn dangling_link(path: &Path, home: &Path) -> Option<PathBuf> {
    let mut current = home.to_path_buf();
    for part in path.strip_prefix(home).ok()?.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).ok()?;
        let nowhere = |e: io::Error| matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR));
        if meta.file_type().is_symlink() && fs::canonicalize(&current).is_err_and(nowhere) {
            return Some(current);
        }
    }
    None
}

/// What is at `path`, a link there not followed. Ok(None): nothing, or a
/// file where a folder would be on the way. Err: whether anything is there
/// could not be told, as below a folder that cannot be looked in.
pub fn presence(path: &Path) -> Result<Option<fs::Metadata>, Gap> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => Ok(None),
        Err(e) => Err(gap(&e)),
    }
}

pub fn open_directory(path: &Path) -> Result<File, Gap> {
    open_path(path, true)?.ok_or("unreadable")
}

/// Whether a path has a '..' or a link in it, its last name included.
fn through_link_or_dot_dot(path: &Path) -> bool {
    let mut at = PathBuf::new();
    path.components().any(|part| {
        at.push(part);
        part == Component::ParentDir
            || fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink())
    })
}

/// The device a path is on. A link at the path is not followed.
fn device(path: &Path) -> Option<u64> {
    fs::symlink_metadata(path).ok().map(|meta| meta.dev())
}

/// Where the volume holding `path` is mounted, kept with a finding so that a
/// later check can tell a file that was removed from one whose drive, share
/// or disk image is not connected. 0: on the device `home` is on, which does
/// not go away while the home folder is there. Otherwise how many leading
/// components of `path` name its mount point: the nearest folder at or above
/// it that is on another device than the folder it is in, or "/". None when
/// that cannot be told. Device numbers are compared here, at one moment, and
/// never kept: a volume can get another one each time it is attached.
pub fn mounted_at(path: &Path, home: &Path) -> Option<u32> {
    let on = device(path)?;
    if device(home)? == on {
        return Some(0);
    }
    let mut point = path;
    for _ in 0..256 {
        match point.parent() {
            Some(above) if device(above)? == on => point = above,
            _ => return u32::try_from(point.components().count()).ok(),
        }
    }
    None
}

/// Whether a volume is still mounted where one was: at the first `count`
/// components of `path`, as `mounted_at` counted them. The folder must be
/// there, and on another device than the folder it is in. "/" is in no
/// folder, and 0 is the home folder's own volume: nothing is asked of either.
/// Another volume mounted at the same place cannot be told from the first.
fn still_mounted(path: &Path, count: u32) -> bool {
    if count == 0 {
        return true;
    }
    let point: PathBuf = path.components().take(count as usize).collect();
    match (device(&point), point.parent()) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(on), Some(above)) => device(above).is_some_and(|outside| outside != on),
    }
}

/// Resolution evidence: a readable regular location or confirmed absence.
/// Links, cloud-only locations, special files, and denied access are not evidence.
/// Nor is a file that is not there while its volume may be what is missing.
/// `mount` is what `mounted_at` said when the file was found, and a volume
/// must still be mounted there. With nothing kept, a folder that cannot be
/// opened is passed by only inside
/// `home`, where deleting a whole folder is the usual clean-up: outside it,
/// the file's own folder must open.
pub fn checked_or_absent(path: &Path, mount: Option<u32>, home: &Path) -> bool {
    if matches!(read_head(path, 0), Ok(Some(_))) {
        return true;
    }
    let climbs = mount.is_some() || path.starts_with(home);
    let mut current = path;
    for _ in 0..128 {
        let Some(parent) = current.parent() else {
            return false;
        };
        match open_directory(parent) {
            Ok(dir) => {
                let Some(name) = current
                    .file_name()
                    .and_then(|n| CString::new(n.as_bytes()).ok())
                else {
                    return false;
                };
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: live directory descriptor, NUL-terminated name and
                // writable stat.
                let absent = unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                    && io::Error::last_os_error().kind() == io::ErrorKind::NotFound;
                // Asked after the file was looked for, so a volume that went
                // away meanwhile is seen to be gone.
                return absent && mount.is_none_or(|count| still_mounted(path, count));
            }
            Err(_) if climbs => current = parent,
            Err(_) => return false,
        }
    }
    false
}

/// New file only (never overwrites, never follows a symlink), mode 0600.
/// Refused, and removed again, if the new file has an access list.
/// As root, the destination directory must be root-owned and not group/other-writable,
/// by its mode or its access list.
pub fn write_export(path: &Path, json: &str, root: bool) -> Result<(), String> {
    // `out/r.json/` and `out/r.json/.` name a folder, yet its last name would
    // be created as a file. Checked as given: `absolute` drops a final '.'.
    let ends_in_name = |last| match last {
        Component::Normal(name) => path.as_os_str().as_bytes().ends_with(name.as_bytes()),
        _ => false,
    };
    if !path.components().next_back().is_some_and(ends_in_name) {
        return Err("export needs a filename".into());
    }
    let path = std::path::absolute(path).map_err(|e| e.to_string())?;
    let dir = path.parent().ok_or("export needs a filename")?;
    // Run as the person, the folder is where its path leads, through links
    // and '..', as for any program: the name below is never followed. As
    // root it is opened without following any, so only root can redirect it.
    let parent = if root {
        open_directory(dir).map_err(|g| {
            if through_link_or_dot_dot(dir) {
                "as root, the path to the export directory must not have a link or '..'".into()
            } else {
                format!("export directory: {g}")
            }
        })?
    } else {
        fs::canonicalize(dir)
            .map_err(|e| gap(&e))
            .and_then(|real| open_directory(&real))
            .map_err(|g| format!("export directory: {g}"))?
    };
    if root {
        let m = parent.metadata().map_err(|e| e.to_string())?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o022 != 0
            || lets_others_change(&parent).map_err(|e| e.to_string())?
        {
            return Err(
                "as root, the export directory must be root-owned and not writable by others"
                    .into(),
            );
        }
    }
    let name = CString::new(
        path.file_name()
            .ok_or("export needs a filename")?
            .as_bytes(),
    )
    .map_err(|_| "invalid export filename")?;
    // Create relative to the same parent handle we checked, not its mutable path.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.kind() {
            io::ErrorKind::AlreadyExists => "file already exists".to_string(),
            _ => e.to_string(),
        });
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut f = unsafe { File::from_raw_fd(fd) };
    // Asked before any byte is written: the file may have taken access
    // entries from its folder, which macOS checks before the mode.
    let refused = match has_access_list(&f) {
        Ok(false) => None,
        Ok(true) => {
            Some("the folder gives new files an access list that may let others read them".into())
        }
        Err(e) => Some(e.to_string()),
    };
    if let Some(e) = refused {
        remove_own(&parent, &name, &f);
        return Err(e);
    }
    let written = f
        .write_all(json.as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| e.to_string());
    if written.is_err() {
        // Part of a report is not a report, and it would keep the name from
        // the next try. Removed only while the name is still this file.
        remove_own(&parent, &name, &f);
    }
    written
}

// macOS's access-list calls, which `libc` does not declare (sys/acl.h).
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

/// Whether an open file has an access list with at least one entry.
fn has_access_list(file: &File) -> io::Result<bool> {
    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    // SAFETY: live descriptor and a valid list type; the call returns a new
    // list for this code to free, or NULL.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(e),
        };
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is the live list just returned and `entry` is writable.
    // The entry points into the list and is not used after it is freed.
    let found = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
    // SAFETY: `acl` came from acl_get_fd_np, is not used again and is freed
    // once.
    unsafe {
        acl_free(acl);
    }
    Ok(found)
}

/// Whether a folder's access list lets others add, remove or rename names in
/// it, or change its access list or owner: an allow entry with any of those
/// rights. A deny entry only takes rights away.
fn lets_others_change(dir: &File) -> io::Result<bool> {
    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    // ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD,
    // ACL_WRITE_SECURITY and ACL_CHANGE_OWNER.
    const CHANGES: [libc::c_int; 5] = [1 << 2, 1 << 5, 1 << 6, 1 << 12, 1 << 13];
    // SAFETY: live descriptor and a valid list type; the call returns a new
    // list for this code to free, or NULL.
    let acl = unsafe { acl_get_fd_np(dir.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(e),
        };
    }
    let (mut which, mut entry) = (ACL_FIRST_ENTRY, std::ptr::null_mut());
    let found = 'entries: {
        // SAFETY: `acl` is the live list just returned and `entry` is
        // writable. Entries and permission sets point into the list, which
        // is freed only after this block.
        while unsafe { acl_get_entry(acl, which, &mut entry) } == 0 {
            which = ACL_NEXT_ENTRY;
            let mut tag = 0;
            // SAFETY: `entry` was just returned for the live list and `tag`
            // is writable.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                break 'entries Err(io::Error::last_os_error());
            }
            if tag != ACL_EXTENDED_ALLOW {
                continue;
            }
            let mut perms = std::ptr::null_mut();
            // SAFETY: as above, with `perms` writable.
            if unsafe { acl_get_permset(entry, &mut perms) } != 0 {
                break 'entries Err(io::Error::last_os_error());
            }
            for perm in CHANGES {
                // SAFETY: `perms` was just returned for a live entry, and
                // `perm` is one of the SDK's acl_perm_t values.
                match unsafe { acl_get_perm_np(perms, perm) } {
                    0 => {}
                    1 => break 'entries Ok(true),
                    _ => break 'entries Err(io::Error::last_os_error()),
                }
            }
        }
        Ok(false)
    };
    // SAFETY: `acl` came from acl_get_fd_np, nothing from it is used again
    // and it is freed once.
    unsafe {
        acl_free(acl);
    }
    found
}

/// Remove `name` from `dir` if it is still the file `file` has open. A file
/// put in its place since, even by the same name, is left as it is.
fn remove_own(dir: &File, name: &CStr, file: &File) {
    let (mut own, mut there) = (
        std::mem::MaybeUninit::<libc::stat>::uninit(),
        std::mem::MaybeUninit::<libc::stat>::uninit(),
    );
    // SAFETY: live descriptor and writable stat.
    if unsafe { libc::fstat(file.as_raw_fd(), own.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: live directory descriptor, NUL-terminated name and writable
    // stat; the name itself is looked at, not what a link there points to.
    let found = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            there.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found != 0 {
        return;
    }
    // SAFETY: fstat and fstatat reported success, so both are filled.
    let (own, there) = unsafe { (own.assume_init(), there.assume_init()) };
    if own.st_dev == there.st_dev && own.st_ino == there.st_ino {
        // SAFETY: live directory descriptor and NUL-terminated name. This
        // removes the name, which was just seen to be this file.
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
        }
    }
}

struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

/// Enumerate the opened handle, not the pathname that could have been swapped.
/// Entries include their directory type. Errors are never silently discarded.
pub struct Listing {
    pub entries: Vec<(PathBuf, bool)>,
    pub gap: Option<Gap>,
    /// The folder the entries were listed from, to read them in with
    /// `read_head_in`. None when there was no folder, or no second handle.
    pub handle: Option<File>,
}

/// Whether a listed entry is a folder. None: it has been removed since it
/// was listed, so there is nothing of it to check.
fn entry_is_directory(fd: libc::c_int, name: &CStr, kind: u8) -> Result<Option<bool>, Gap> {
    if kind != libc::DT_UNKNOWN {
        return Ok(Some(kind == libc::DT_DIR));
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: live parent descriptor, NUL-terminated name and writable stat.
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(gap(&e))
        };
    }
    // SAFETY: fstatat reported success, so it filled the stat.
    let stat = unsafe { stat.assume_init() };
    Ok(Some(stat.st_mode & libc::S_IFMT == libc::S_IFDIR))
}

pub fn list_dir(dir: &Path, required: bool, remaining: &mut usize) -> Result<Listing, Gap> {
    listing(open_path(dir, true)?, dir, required, remaining)
}

/// Paths deeper than this are opened from "/" each time, which bounds the
/// descriptors `Folders` keeps open.
const KEPT: usize = 32;

/// The folders above the last one `Folders::list` listed, open, so that
/// listing the next opens only the names below what the two share instead of
/// walking from "/" again: in a breadth-first walk, walking from "/" is most
/// of the time spent opening folders. Each is opened from the one above it as
/// `open_path` opens them, without following links. One kept here is used as
/// it was opened: if its path is swapped for a link after that, what is
/// listed is still in the folder, never behind the link, as for the entries
/// read from a listed folder's `handle`.
#[derive(Default)]
pub struct Folders {
    root: Option<File>,
    /// Each folder below "/", by name, down to the last listed one's parent.
    above: Vec<(std::ffi::OsString, File)>,
}

impl Folders {
    /// As `list_dir`.
    pub fn list(
        &mut self,
        dir: &Path,
        required: bool,
        remaining: &mut usize,
    ) -> Result<Listing, Gap> {
        let folder = self.open(dir)?;
        listing(folder, dir, required, remaining)
    }

    /// As `open_path(dir, true)`, through the folders kept.
    fn open(&mut self, dir: &Path) -> Result<Option<File>, Gap> {
        if !dir.is_absolute() {
            return Err("unreadable");
        }
        let mut names = Vec::new();
        for component in dir.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => names.push(name),
                _ => return Err("unreadable"),
            }
        }
        let Some((name, parents)) = names.split_last().filter(|_| names.len() <= KEPT) else {
            return open_path(dir, true);
        };
        let shared = self
            .above
            .iter()
            .zip(parents)
            .take_while(|((kept, _), name)| kept.as_os_str() == **name)
            .count();
        self.above.truncate(shared);
        let root = match &mut self.root {
            Some(root) => root,
            empty => empty.insert(File::open("/").map_err(|e| gap(&e))?),
        };
        // `shared` counts names zipped with `parents`, so it is at most its length.
        for parent in &parents[shared..] {
            let above = self.above.last().map_or(&*root, |(_, folder)| folder);
            let Some(folder) = open_at(above, parent, true)? else {
                return Ok(None);
            };
            self.above.push((parent.to_os_string(), folder));
        }
        open_at(
            self.above.last().map_or(&*root, |(_, folder)| folder),
            name,
            true,
        )
    }
}

/// The listing of the folder `file` opened at `dir`, as `list_dir` gives it.
fn listing(
    file: Option<File>,
    dir: &Path,
    required: bool,
    remaining: &mut usize,
) -> Result<Listing, Gap> {
    let Some(file) = file else {
        return if required {
            Err("unreadable")
        } else {
            Ok(Listing {
                entries: Vec::new(),
                gap: None,
                handle: None,
            })
        };
    };
    // The listing closes its own descriptor; this one stays open for reads.
    let handle = file.try_clone().ok();
    let fd = file.into_raw_fd();
    let ptr = unsafe { libc::fdopendir(fd) };
    if ptr.is_null() {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(gap(&e));
    }
    let stream = Directory(ptr);
    let mut out = Vec::new();
    let mut incomplete = None;
    loop {
        let errno = unsafe { libc::__error() };
        unsafe {
            *errno = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *errno } != 0 {
                incomplete = Some(gap(&io::Error::last_os_error()));
            }
            break;
        }
        // SAFETY: readdir's name is valid until the next call on this stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if out.len() == FOLDER_ENTRIES || *remaining == 0 {
            incomplete = Some("scan-limit");
            break;
        }
        *remaining -= 1;
        // Type is only a traversal hint. Later opens still check symlinks,
        // handle types and cloud flags. Some filesystems omit this hint.
        let kind = unsafe { (*entry).d_type };
        let is_dir = match entry_is_directory(fd, name, kind) {
            Ok(Some(is_dir)) => is_dir,
            Ok(None) => continue,
            Err(g) => {
                incomplete = Some(g);
                break;
            }
        };
        out.push((dir.join(OsStr::from_bytes(name.to_bytes())), is_dir));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Listing {
        entries: out,
        gap: incomplete,
        handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolution_does_not_follow_links_or_accept_special_files() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-resolution-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("regular"), b"synthetic").unwrap();
        // With nothing kept about a volume, and `root` as the home folder.
        assert!(checked_or_absent(&root.join("regular"), None, &root));
        assert!(checked_or_absent(&root.join("absent"), None, &root));
        assert!(checked_or_absent(
            &root.join("missing-parent/absent"),
            None,
            &root
        ));
        std::os::unix::fs::symlink(root.join("regular"), root.join("link")).unwrap();
        assert!(!checked_or_absent(&root.join("link"), None, &root));
        std::os::unix::fs::symlink(&root, root.join("parent-link")).unwrap();
        assert!(!checked_or_absent(
            &root.join("parent-link/absent"),
            None,
            &root
        ));
        let fifo = CString::new(root.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(!checked_or_absent(&root.join("fifo"), None, &root));
        for name in ["regular", "link", "parent-link", "fifo"] {
            fs::remove_file(root.join(name)).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn entries_read_from_a_listed_folder_are_checked_as_paths_are() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-listed-{}", std::process::id()));
        let dir = root.join("dir");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::create_dir(root.join("elsewhere")).unwrap();
        fs::write(dir.join("regular"), b"synthetic listed").unwrap();
        fs::write(root.join("elsewhere/regular"), b"synthetic elsewhere").unwrap();
        std::os::unix::fs::symlink(dir.join("regular"), dir.join("link")).unwrap();
        let fifo = CString::new(dir.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut remaining = 100;
        let listing = list_dir(&dir, true, &mut remaining).unwrap();
        assert_eq!(listing.entries.len(), 4);
        let handle = listing.handle.expect("the listed folder stays open");
        let read =
            |name: &str| read_head_in(&handle, name.as_ref(), 4096).map(|h| h.map(|h| h.bytes));
        let whole =
            |name: &str| read_config_in(&handle, name.as_ref(), 4096).map(|h| h.map(|h| h.bytes));
        // As `read_head` and `read_config` answer for the same paths.
        for name in ["regular", "link", "fifo", "sub", "absent"] {
            let path = dir.join(name);
            assert_eq!(
                read(name),
                read_head(&path, 4096).map(|h| h.map(|h| h.bytes)),
                "{name}"
            );
            assert_eq!(
                whole(name),
                read_config(&path, 4096).map(|h| h.map(|h| h.bytes)),
                "{name}"
            );
        }
        assert_eq!(read("regular"), Ok(Some(b"synthetic listed".to_vec())));
        assert_eq!(read("link"), Ok(None));
        // The folder's path swapped for a link after it was listed: what is
        // read is in the folder that was listed, never behind the link.
        fs::rename(&dir, root.join("moved")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), &dir).unwrap();
        assert_eq!(
            read_head(&dir.join("regular"), 4096).map(|h| h.is_none()),
            Ok(true)
        );
        assert_eq!(read("regular"), Ok(Some(b"synthetic listed".to_vec())));
        fs::remove_dir_all(root).unwrap();
    }

    /// How many names a path has, as `mounted_at` counts a mount point.
    fn names(path: &Path) -> Option<u32> {
        u32::try_from(path.components().count()).ok()
    }

    #[test]
    fn cached_parent_reads_stay_on_the_original_directory() {
        for link in [true, false] {
            let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
                "credential-cached-reads-{}-{link}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("parent/child")).unwrap();
            fs::create_dir_all(root.join("replacement/child")).unwrap();
            fs::write(root.join("parent/child/same"), b"synthetic original").unwrap();
            fs::write(
                root.join("replacement/child/same"),
                b"synthetic replacement",
            )
            .unwrap();
            let mut folders = Folders::default();
            folders
                .list(&root.join("parent/child"), true, &mut 100)
                .unwrap();
            fs::rename(root.join("parent"), root.join("moved")).unwrap();
            if link {
                std::os::unix::fs::symlink(root.join("replacement"), root.join("parent")).unwrap();
            } else {
                fs::rename(root.join("replacement"), root.join("parent")).unwrap();
            }
            let listing = folders
                .list(&root.join("parent/child"), true, &mut 100)
                .unwrap();
            let handle = listing.handle.unwrap();
            let read = read_head_in(&handle, "same".as_ref(), 4096)
                .unwrap()
                .unwrap();
            assert!(read.bytes == b"synthetic original");
            let by_path = read_head(&root.join("parent/child/same"), 4096).unwrap();
            if link {
                assert!(by_path.is_none());
            } else {
                assert!(by_path.unwrap().bytes == b"synthetic replacement");
            }
            drop(handle);
            drop(folders);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn cached_folder_entry_budgets_match_path_listings() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-cached-budgets-{}", std::process::id()));
        let dir = root.join("parent/child");
        fs::create_dir_all(&dir).unwrap();
        for name in ["one", "two", "three"] {
            fs::write(dir.join(name), b"synthetic").unwrap();
        }
        for warm in [false, true] {
            for budget in [0, 2, 3, 4] {
                let mut folders = Folders::default();
                if warm {
                    folders.list(&dir, true, &mut 100).unwrap();
                }
                let (mut cached_budget, mut path_budget) = (budget, budget);
                let cached = folders.list(&dir, true, &mut cached_budget).unwrap();
                let walked = list_dir(&dir, true, &mut path_budget).unwrap();
                assert_eq!(cached.entries, walked.entries);
                assert_eq!(cached.gap, walked.gap);
                assert_eq!(cached.handle.is_some(), walked.handle.is_some());
                assert_eq!(cached_budget, path_budget);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn folders_listed_in_turn_are_listed_as_paths_are() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-folders-{}", std::process::id()));
        for dir in ["a/b/c", "a/b/d", "a/e", "f", "elsewhere/c"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("a/b/c/one"), b"synthetic").unwrap();
        fs::write(root.join("a/b/d/two"), b"synthetic").unwrap();
        fs::write(root.join("a/file"), b"synthetic").unwrap();
        fs::write(root.join("elsewhere/c/other"), b"synthetic elsewhere").unwrap();
        std::os::unix::fs::symlink(root.join("a/b"), root.join("a/link")).unwrap();
        // Deeper than the folders kept open, with every folder on the way.
        let deep = (0..KEPT).fold(root.join("f"), |path, _| path.join("g"));
        fs::create_dir_all(&deep).unwrap();
        let listed = |listing: Result<Listing, Gap>| {
            listing.map(|listing| (listing.entries, listing.gap, listing.handle.is_some()))
        };
        let mut folders = Folders::default();
        // Down, across, up, to the sibling of a parent, through a link, at a
        // file, at nothing, and below each of those.
        for (path, required) in [
            ("a", true),
            ("a/b", true),
            ("a/b/c", true),
            ("a/b/d", false),
            ("a/e", false),
            ("a/b", false),
            ("f", true),
            ("a/b/c", false),
            ("a/link", false),
            ("a/link", true),
            ("a/link/c", false),
            ("a/file", false),
            ("a/file", true),
            ("a/file/c", false),
            ("absent", false),
            ("absent", true),
            ("absent/c", true),
            ("a/b/../b", true),
            ("", true),
        ] {
            let dir = root.join(path);
            let (mut kept, mut walked) = (100, 100);
            assert_eq!(
                listed(folders.list(&dir, required, &mut kept)),
                listed(list_dir(&dir, required, &mut walked)),
                "{path}"
            );
            assert_eq!(kept, walked, "{path}");
        }
        for dir in deep
            .ancestors()
            .take_while(|dir| dir.starts_with(root.join("f")))
        {
            let (mut kept, mut walked) = (100, 100);
            assert_eq!(
                listed(folders.list(dir, true, &mut kept)),
                listed(list_dir(dir, true, &mut walked))
            );
        }
        // The path of a folder kept open swapped for a link: what is listed
        // below it is in the folder that was opened, never behind the link.
        let mut remaining = 100;
        folders
            .list(&root.join("a/b/c"), true, &mut remaining)
            .unwrap();
        fs::rename(root.join("a/b"), root.join("moved")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), root.join("a/b")).unwrap();
        assert_eq!(
            list_dir(&root.join("a/b/c"), true, &mut remaining).map(|l| l.entries),
            Err("unreadable")
        );
        for (dir, file) in [("a/b/c", "one"), ("a/b/d", "two")] {
            let listing = folders.list(&root.join(dir), true, &mut remaining).unwrap();
            assert_eq!(listing.entries, vec![(root.join(dir).join(file), false)]);
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// As root, an export folder must not let others add, remove or swap
    /// names in it, or give themselves that right, through its access list
    /// any more than through its mode. Deny entries, and allow entries that
    /// grant none of it, are accepted. Only the access list is asked here,
    /// so this needs no root.
    #[test]
    fn a_folder_access_list_that_lets_others_change_it_is_seen() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-folder-access-{}", std::process::id()));
        let cases: [(&[&str], bool); 9] = [
            (&[], false),
            (
                &["group:everyone allow list,search,readattr,readsecurity,file_inherit"],
                false,
            ),
            (
                &["group:everyone deny add_file,add_subdirectory,delete_child,writesecurity,chown"],
                false,
            ),
            (&["group:everyone allow add_file"], true),
            (&["group:everyone allow add_subdirectory"], true),
            (&["group:everyone allow delete_child"], true),
            (&["group:everyone allow writesecurity"], true),
            (&["group:everyone allow chown"], true),
            // Past the first entry: `chmod +a` puts deny entries first and
            // a new allow entry before older ones, so this one ends up last.
            (
                &[
                    "group:everyone deny add_file",
                    "user:nobody allow delete_child",
                    "group:staff allow list,search",
                ],
                true,
            ),
        ];
        for (i, (entries, changes)) in cases.into_iter().enumerate() {
            let dir = root.join(i.to_string());
            fs::create_dir_all(&dir).unwrap();
            for entry in entries {
                let chmod = std::process::Command::new("/bin/chmod")
                    .args(["+a", entry])
                    .arg(&dir)
                    .output()
                    .unwrap();
                assert!(chmod.status.success(), "{entry}: {chmod:?}");
            }
            let handle = open_directory(&dir).unwrap();
            assert_eq!(lets_others_change(&handle).unwrap(), changes, "{entries:?}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_file_gone_with_its_volume_is_not_known_to_be_removed() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-absence-{}", std::process::id()));
        let home = root.join("home");
        fs::create_dir_all(home.join("kept")).unwrap();
        fs::create_dir_all(root.join("drive/kept")).unwrap();
        let absent = |path: &str, mount| checked_or_absent(&root.join(path), mount, &home);
        // Found on the device the home folder is on, which does not go away:
        // a file gone from its folder, or with its folder, was removed.
        let on_drive = ["drive/absent", "drive/kept/absent", "drive/gone/absent"];
        for path in on_drive
            .into_iter()
            .chain(["home/kept/absent", "home/gone/absent"])
        {
            assert!(absent(path, Some(0)), "{path}");
        }
        // Found on a volume of its own, mounted at `drive`. Nothing is
        // mounted there now: the folder is on the device of the folder it is
        // in. What is not in it was not removed, as far as anyone can tell.
        let drive = names(&root.join("drive"));
        for path in on_drive {
            assert!(!absent(path, drive), "{path}");
        }
        // The same in the home folder: a share's mount point, left empty.
        let share = names(&home.join("kept"));
        for path in ["home/kept/absent", "home/kept/gone/absent"] {
            assert!(!absent(path, share), "{path}");
        }
        // A mount point that is not there at all, as after a drive is
        // ejected, and a count the path does not have names for.
        let ejected = names(&root.join("ejected"));
        for path in ["ejected/absent", "ejected/dir/absent"] {
            assert!(!absent(path, ejected), "{path}");
        }
        assert!(!absent("drive/absent", Some(u32::MAX)));
        // Mounted at "/", which is in no folder to be compared with.
        for path in ["drive/kept/absent", "drive/gone/absent"] {
            assert!(absent(path, Some(1)), "{path}");
        }
        // Nothing kept: in the home folder as it was, and outside it only
        // when the file's own folder can be opened.
        for path in ["home/kept/absent", "home/gone/absent", "drive/kept/absent"] {
            assert!(absent(path, None), "{path}");
        }
        assert!(!absent("drive/gone/absent", None));
        // A volume that is mounted, where the system has one at /dev: a
        // file not there is gone, and so is its folder.
        let (dev, top) = (Path::new("/dev"), Path::new("/"));
        if device(dev).is_some() && device(dev) != device(top) {
            let gone = format!("/dev/credential-absence-{}", std::process::id());
            let gone = Path::new(&gone).join("absent");
            assert!(checked_or_absent(&gone, names(dev), &home));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_mount_point_is_kept_as_a_count_of_names() {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-mounted-{}", std::process::id()));
        let home = root.join("home");
        fs::create_dir_all(home.join("dir")).unwrap();
        fs::create_dir_all(root.join("drive/dir")).unwrap();
        let file = root.join("drive/dir/file");
        fs::write(&file, b"synthetic").unwrap();
        fs::write(home.join("dir/file"), b"synthetic").unwrap();
        // What a test can make is on the device its home folder is on.
        for path in [&home.join("dir/file"), &home.join("dir"), &file] {
            assert_eq!(mounted_at(path, &home), Some(0), "{path:?}");
        }
        // Not there, or no home folder to compare with: it cannot be told.
        assert_eq!(mounted_at(&root.join("absent"), &home), None);
        assert_eq!(mounted_at(&file, &root.join("absent")), None);
        // Another device, where the system mounts one at /dev.
        let dev = Path::new("/dev");
        if device(dev).is_some() && device(dev) != device(&home) {
            // What is on it is mounted there: two names, "/" and "dev".
            if device(dev) != device(Path::new("/")) {
                assert_eq!(mounted_at(&dev.join("null"), &home), Some(2));
                assert_eq!(mounted_at(dev, &home), Some(2));
            }
            // A link is on the device it is stored on, not the one it leads to.
            std::os::unix::fs::symlink(dev.join("null"), root.join("link")).unwrap();
            assert_eq!(mounted_at(&root.join("link"), &home), Some(0));
            // As if the home folder were on that device, and the file so on
            // another. Its mount point is the nearest folder above it that is
            // on another device than the folder it is in, or "/".
            let count = mounted_at(&file, dev).unwrap();
            let point: PathBuf = file.components().take(count as usize).collect();
            assert!(count >= 1 && file.starts_with(&point));
            assert_eq!(device(&point), device(&file));
            assert!(point
                .parent()
                .is_none_or(|above| device(above) != device(&point)));
            for inside in file.ancestors().take_while(|a| *a != point) {
                assert_eq!(device(inside), device(&file), "{inside:?}");
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn links_resolve_only_to_places_inside_home() {
        use std::os::unix::fs::PermissionsExt;
        let base = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-links-{}", std::process::id()));
        let home = base.join("home");
        fs::create_dir_all(home.join("dotfiles/aws")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(home.join("dotfiles/npmrc"), b"synthetic").unwrap();
        fs::write(home.join("dotfiles/aws/credentials"), b"synthetic").unwrap();
        fs::write(base.join("outside/credentials"), b"synthetic").unwrap();
        let link = |to: PathBuf, at: PathBuf| std::os::unix::fs::symlink(to, at);
        // A linked file, a linked parent folder, and a plain file.
        link(home.join("dotfiles/npmrc"), home.join(".npmrc")).unwrap();
        link(home.join("dotfiles/aws"), home.join(".aws")).unwrap();
        assert_eq!(
            through_links(&home.join(".npmrc"), &home),
            Some(Ok(home.join("dotfiles/npmrc")))
        );
        assert_eq!(
            through_links(&home.join(".aws/credentials"), &home),
            Some(Ok(home.join("dotfiles/aws/credentials")))
        );
        assert_eq!(through_links(&home.join("dotfiles/npmrc"), &home), None);
        assert_eq!(through_links(&home.join("absent"), &home), None);
        // Outside the home, a loop, and a link to nothing.
        link(base.join("outside"), home.join(".kube")).unwrap();
        link(home.join("loop"), home.join("loop")).unwrap();
        link(home.join("absent"), home.join("dangling")).unwrap();
        assert_eq!(
            through_links(&home.join(".kube/credentials"), &home),
            Some(Err("symlink"))
        );
        assert_eq!(
            through_links(&home.join("loop"), &home),
            Some(Err("unreadable"))
        );
        assert_eq!(through_links(&home.join("dangling"), &home), None);
        // Below a link to a file, in the home or outside it: nothing.
        link(base.join("outside/credentials"), home.join("socket")).unwrap();
        assert_eq!(through_links(&home.join(".npmrc/config"), &home), None);
        assert_eq!(through_links(&home.join("socket/config"), &home), None);
        // Into a folder inside the home that cannot be opened.
        link(home.join("dotfiles/aws"), home.join(".config")).unwrap();
        let none = fs::Permissions::from_mode(0o000);
        fs::set_permissions(home.join("dotfiles"), none).unwrap();
        let locked = through_links(&home.join(".config/credentials"), &home);
        fs::set_permissions(home.join("dotfiles"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(locked, Some(Err("permission-denied")));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn as_root_a_link_or_dot_dot_before_the_export_folder_is_refused_by_name() {
        let base = PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("credential-export-root-{}", std::process::id()));
        fs::create_dir_all(base.join("real")).unwrap();
        std::os::unix::fs::symlink("real", base.join("link")).unwrap();
        for path in [
            base.join("link/report.json"),
            base.join("real/../real/report.json"),
        ] {
            let refused = write_export(&path, "{}", true).unwrap_err();
            assert!(refused.contains("a link or '..'"), "{path:?}: {refused}");
        }
        assert!(fs::read_dir(base.join("real")).unwrap().next().is_none());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn unknown_entry_types_use_nofollow_metadata() {
        let path = PathBuf::from(std::env::var_os("TMPDIR").expect("set TMPDIR"))
            .join(format!("credential-entry-types-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("dir")).unwrap();
        fs::write(path.join("file"), b"synthetic data").unwrap();
        std::os::unix::fs::symlink(path.join("dir"), path.join("link")).unwrap();
        let parent = open_directory(&path).unwrap();
        for (name, expected) in [("dir", true), ("file", false), ("link", false)] {
            let name = CString::new(name).unwrap();
            assert_eq!(
                entry_is_directory(parent.as_raw_fd(), &name, libc::DT_UNKNOWN),
                Ok(Some(expected))
            );
        }
        // Known hints avoid metadata calls, but cannot authorize a later read.
        let absent = CString::new("absent").unwrap();
        assert_eq!(
            entry_is_directory(parent.as_raw_fd(), &absent, libc::DT_DIR),
            Ok(Some(true))
        );
        // An entry removed since it was listed is passed by, not a gap that
        // would end the listing of the whole folder.
        assert_eq!(
            entry_is_directory(parent.as_raw_fd(), &absent, libc::DT_UNKNOWN),
            Ok(None)
        );
        let below = CString::new("file/below").unwrap();
        assert_eq!(
            entry_is_directory(parent.as_raw_fd(), &below, libc::DT_UNKNOWN),
            Err("unreadable")
        );
        fs::remove_dir_all(path).unwrap();
    }
}
