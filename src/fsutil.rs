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

fn is_dataless(meta: &fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt as MacExt;
    const SF_DATALESS: u32 = 0x4000_0000;
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
    let Some(file) = open_path(path, false)? else {
        return Ok(None);
    };
    let meta = file.metadata().map_err(|e| gap(&e))?;
    let mut bytes = Vec::new();
    file.take(max)
        .read_to_end(&mut bytes)
        .map_err(|e| gap(&e))?;
    Ok(Some(Head {
        bytes,
        shared: meta.mode() & 0o044 != 0,
    }))
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
    let Some(mut file) = open_path(path, false)? else {
        return Ok(None);
    };
    let before = file.metadata().map_err(|e| gap(&e))?;
    if before.len() > max {
        return Err("too-large");
    }
    let mut bytes = Vec::new();
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
    Ok(Some(Head {
        bytes,
        shared: before.mode() & 0o044 != 0,
    }))
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
        let name = CString::new(name.as_bytes()).map_err(|_| "unreadable")?;
        let want_dir = directory || i + 1 < parts.len();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live parent descriptor, NUL-terminated name and writable stat.
        if unsafe {
            libc::fstatat(
                file.as_raw_fd(),
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
        if stat.st_flags & 0x4000_0000 != 0 {
            return Err("cloud-only-file");
        }
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if want_dir { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
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
        file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(|e| gap(&e))?;
        if (want_dir && !meta.is_dir()) || (!want_dir && !meta.is_file()) {
            return Ok(None);
        }
        if is_dataless(&meta) {
            return Err("cloud-only-file");
        }
    }
    Ok(Some(file))
}

/// Where a path under `home` really is, when it or a folder above it is a
/// symbolic link. None: no link on the way, or nothing there. Some(Ok): the
/// real location, which is inside `home` and is then opened without following
/// links like any other path. Some(Err): the link leads outside `home` or
/// cannot be resolved, and is not followed.
pub fn through_links(path: &Path, home: &Path) -> Option<Result<PathBuf, ()>> {
    let mut current = home.to_path_buf();
    for part in path.strip_prefix(home).ok()?.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return match fs::canonicalize(path) {
                    Ok(real) if real.starts_with(home) => Some(Ok(real)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                    _ => Some(Err(())),
                };
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

pub fn open_directory(path: &Path) -> Result<File, Gap> {
    open_path(path, true)?.ok_or("unreadable")
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
/// must still be mounted there. With nothing kept, as for an item listed
/// before this was, a folder that cannot be opened is passed by only inside
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
/// As root, the destination directory must be root-owned and not group/other-writable.
pub fn write_export(path: &Path, json: &str, root: bool) -> Result<(), String> {
    let path = std::path::absolute(path).map_err(|e| e.to_string())?;
    let dir = path.parent().ok_or("export needs a filename")?;
    let parent = open_directory(dir).map_err(|g| format!("export directory: {g}"))?;
    if root {
        let m = parent.metadata().map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
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
    f.write_all(json.as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| e.to_string())
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
}

fn entry_is_directory(fd: libc::c_int, name: &CStr, kind: u8) -> Result<bool, Gap> {
    if kind != libc::DT_UNKNOWN {
        return Ok(kind == libc::DT_DIR);
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
        return Err(gap(&io::Error::last_os_error()));
    }
    Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

pub fn list_dir(dir: &Path, required: bool, remaining: &mut usize) -> Result<Listing, Gap> {
    let Some(file) = open_path(dir, true)? else {
        return if required {
            Err("unreadable")
        } else {
            Ok(Listing {
                entries: Vec::new(),
                gap: None,
            })
        };
    };
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
        if out.len() == 10_000 || *remaining == 0 {
            incomplete = Some("scan-limit");
            break;
        }
        *remaining -= 1;
        // Type is only a traversal hint. Later opens still check symlinks,
        // handle types and cloud flags. Some filesystems omit this hint.
        let kind = unsafe { (*entry).d_type };
        let is_dir = match entry_is_directory(fd, name, kind) {
            Ok(is_dir) => is_dir,
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

    /// How many names a path has, as `mounted_at` counts a mount point.
    fn names(path: &Path) -> Option<u32> {
        Some(path.components().count() as u32)
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
        // Nothing kept, as for an item listed before this was: in the home
        // folder as it was, and outside it only when the file's own folder
        // can be opened.
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
            Some(Err(()))
        );
        assert_eq!(through_links(&home.join("loop"), &home), Some(Err(())));
        assert_eq!(through_links(&home.join("dangling"), &home), None);
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
                Ok(expected)
            );
        }
        // Known hints avoid metadata calls, but cannot authorize a later read.
        let absent = CString::new("absent").unwrap();
        assert_eq!(
            entry_is_directory(parent.as_raw_fd(), &absent, libc::DT_DIR),
            Ok(true)
        );
        assert_eq!(
            entry_is_directory(parent.as_raw_fd(), &absent, libc::DT_UNKNOWN),
            Err("unreadable")
        );
        fs::remove_dir_all(path).unwrap();
    }
}
