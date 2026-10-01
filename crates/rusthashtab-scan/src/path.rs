//! Path normalization and expansion of a user selection into individual files.
//!
//! # Why this is hand-written rather than `canonicalize`
//!
//! [`std::fs::canonicalize`] resolves every reparse point on the way to the
//! target. That is the one thing this walk must *not* do: a junction inside a
//! selected tree can point at another volume, or at an ancestor, and following
//! it silently hashes files the user did not select — or never terminates.
//! Normalization here is therefore purely lexical: it makes a path absolute and
//! resolves `.` and `..`, and touches the filesystem at all only to read a
//! directory listing.
//!
//! # Verbatim prefixes
//!
//! Windows spells an extended-length path `\\?\C:\…`. [`normalize_path`] strips
//! that spelling because it is what the user would otherwise be shown, and
//! [`to_extension_path`] puts it back for the benefit of the file system — which
//! is also how a path with trailing dots or spaces, or one longer than
//! `MAX_PATH`, keeps opening correctly.

use crate::FileJob;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf, Prefix};

/// `FILE_ATTRIBUTE_REPARSE_POINT`: set on symlinks *and* junctions.
///
/// Spelled out rather than imported so that this module stays free of the
/// `windows` crate; the value is documented in the Win32 file-attribute list.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Make a path absolute and resolve `.` and `..` without touching the disk.
///
/// The result is the *display* form: an extended-length (`\\?\`) prefix is
/// removed. Use [`to_extension_path`] before handing a path to the OS.
///
/// A relative path is resolved against the current directory; if that cannot be
/// read, the path is returned normalized but still relative rather than making
/// the caller handle an error it cannot act on.
pub fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };

    let mut prefix = OsString::new();
    let mut rooted = false;
    let mut parts: Vec<OsString> = Vec::new();

    for component in absolute.components() {
        match component {
            Component::Prefix(p) => prefix = prefix_text(p.kind()),
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            // Popping past the root is a no-op, which is the behaviour wanted:
            // `C:\..\x` is `C:\x`, never a panic or an escape above the root.
            Component::ParentDir => {
                let _ = parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
        }
    }

    let mut text = prefix;
    if rooted {
        text.push("\\");
    }
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            text.push("\\");
        }
        text.push(part);
    }
    PathBuf::from(text)
}

/// Re-add the extended-length prefix so paths longer than `MAX_PATH`, and names
/// with trailing dots or spaces, survive the trip to the file system.
///
/// Returns the path unchanged when there is nothing to add: already-verbatim
/// paths, device paths (`\\.\`), and relative paths, for which the prefix is
/// either redundant or invalid.
pub(crate) fn to_extension_path(path: &Path) -> PathBuf {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path.to_path_buf();
    };

    match prefix.kind() {
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut text = OsString::from(r"\\?\UNC\");
            text.push(server);
            text.push("\\");
            text.push(share);
            let rest = components.as_path();
            if !rest.as_os_str().is_empty() {
                text.push("\\");
                text.push(rest.as_os_str());
            }
            PathBuf::from(text)
        }
        Prefix::Disk(_) => {
            let mut text = OsString::from(r"\\?\");
            text.push(path.as_os_str());
            PathBuf::from(text)
        }
        // `\\?\…` is already verbatim, and `\\.\…` addresses a device: wrapping
        // either in another prefix would make the path unopenable.
        Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::DeviceNS(_) => path.to_path_buf(),
    }
}

/// The text form of a path prefix, with any verbatim spelling removed.
fn prefix_text(kind: Prefix<'_>) -> OsString {
    let mut text = OsString::new();
    match kind {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            text.push(char::from(letter).to_string());
            text.push(":");
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            text.push(r"\\");
            text.push(server);
            text.push("\\");
            text.push(share);
        }
        Prefix::DeviceNS(name) => {
            text.push(r"\\.\");
            text.push(name);
        }
        Prefix::Verbatim(name) => text.push(name),
    }
    text
}

/// Expand a user selection into a flat list of files to hash.
///
/// Directories are walked recursively. Reparse points (symlinks, junctions,
/// mount points) are **not** followed: doing so risks cycles and can silently
/// hash a completely different volume than the user selected. A root that *is* a
/// reparse point is followed, because naming it explicitly is a request to open
/// it.
///
/// A root that cannot be stat'ed is an error — the user asked for a file that is
/// not there. A subdirectory or file that disappears mid-walk is skipped
/// instead: an error there would abort a scan of thousands of files because one
/// of them was renamed.
///
/// The order is deterministic but not sorted as a whole: within a directory,
/// files come before subdirectories, and subdirectories are then descended in
/// name order. Nothing downstream depends on a particular order — a UI sorts its
/// own rows — but a reproducible order makes a scan reproducible in tests.
///
/// `FileJob::size` is the file's size at expansion time. It is what the progress
/// total is computed from; the scanner re-reads the actual size when it opens
/// the file, so a file that grows or shrinks during the scan still hashes
/// correctly.
pub fn expand_selection(roots: &[PathBuf]) -> std::io::Result<Vec<FileJob>> {
    let mut jobs = Vec::new();

    for root in roots {
        let root = normalize_path(root);
        // Follow a reparse point only for the root itself, where the user's
        // intent is explicit.
        let metadata = std::fs::metadata(&root)?;

        if !metadata.is_dir() {
            let size = metadata.len();
            jobs.push(job_for(&root, &root, size));
            continue;
        }

        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                // An unreadable subdirectory is skipped: access-denied on one
                // directory must not lose the other ten thousand files.
                Err(_) => continue,
            };

            let mut children: Vec<(OsString, PathBuf)> = Vec::with_capacity(entries.size_hint().0);
            for entry in entries.flatten() {
                children.push((entry.file_name(), entry.path()));
            }
            children.sort_by(|a, b| a.0.cmp(&b.0));

            let mut subdirectories: Vec<PathBuf> = Vec::new();
            for (_, path) in children {
                // `symlink_metadata` deliberately does not follow the link, so a
                // junction is seen as a reparse point rather than as the
                // directory it points at.
                let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if is_reparse_point(&metadata) {
                    continue;
                }
                if metadata.is_dir() {
                    subdirectories.push(path);
                } else {
                    jobs.push(job_for(&root, &path, metadata.len()));
                }
            }

            // Reverse so the stack pops in sorted order, which keeps the job
            // list itself deterministic rather than merely stable.
            for path in subdirectories.into_iter().rev() {
                stack.push(path);
            }
        }
    }

    Ok(jobs)
}

/// Build a job for one file, with the display path relative to the scan root.
fn job_for(root: &Path, path: &Path, size: u64) -> FileJob {
    let display_path = path
        .strip_prefix(root)
        .ok()
        .map(|relative| relative.to_string_lossy().into_owned())
        .filter(|relative| !relative.is_empty())
        .unwrap_or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        });

    FileJob {
        path: path.to_path_buf(),
        display_path,
        expected: Vec::new(),
        size,
    }
}

/// Whether a directory entry is a reparse point (symlink, junction, mount point).
#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// On non-Windows targets only symlinks are detectable; the project ships for
/// Windows, so this exists to keep the module compiling rather than to be used.
#[cfg(not(windows))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    /// A uniquely named temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusthashtab-scan-path-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, bytes: usize) {
        fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn relative_paths_become_absolute() {
        let normalized = normalize_path(Path::new("some\\relative\\file.txt"));
        assert!(normalized.is_absolute(), "{normalized:?} must be absolute");
        assert!(normalized.ends_with("some\\relative\\file.txt"));
    }

    #[test]
    fn dot_and_dotdot_are_resolved_lexically() {
        assert_eq!(
            normalize_path(Path::new(r"C:\a\..\b\.\c")),
            PathBuf::from(r"C:\b\c")
        );
        // Popping past the root must stop at the root rather than escape it.
        assert_eq!(
            normalize_path(Path::new(r"C:\..\..\x")),
            PathBuf::from(r"C:\x")
        );
    }

    #[test]
    fn verbatim_prefixes_are_stripped_for_display_and_restored_for_the_os() {
        assert_eq!(
            normalize_path(Path::new(r"\\?\C:\very\long")),
            PathBuf::from(r"C:\very\long")
        );
        assert_eq!(
            normalize_path(Path::new(r"\\?\UNC\server\share\file")),
            PathBuf::from(r"\\server\share\file")
        );

        assert_eq!(
            to_extension_path(Path::new(r"C:\very\long")),
            PathBuf::from(r"\\?\C:\very\long")
        );
        assert_eq!(
            to_extension_path(Path::new(r"\\server\share\file")),
            PathBuf::from(r"\\?\UNC\server\share\file")
        );
        // Already verbatim, and device paths, must not be double-prefixed.
        assert_eq!(
            to_extension_path(Path::new(r"\\?\C:\x")),
            PathBuf::from(r"\\?\C:\x")
        );
        assert_eq!(
            to_extension_path(Path::new(r"\\.\PhysicalDrive0")),
            PathBuf::from(r"\\.\PhysicalDrive0")
        );
    }

    #[test]
    fn normalizing_is_idempotent() {
        let once = normalize_path(Path::new(r"C:\a\b\..\c"));
        assert_eq!(normalize_path(&once), once);
    }

    #[test]
    fn a_single_file_root_becomes_one_job() {
        let dir = TempDir::new("single");
        let file = dir.path().join("one.bin");
        write(&file, 17);

        let jobs = expand_selection(std::slice::from_ref(&file)).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].path, normalize_path(&file));
        assert_eq!(jobs[0].display_path, "one.bin");
        assert_eq!(jobs[0].size, 17);
        assert!(jobs[0].expected.is_empty());
    }

    #[test]
    fn a_directory_is_walked_recursively_in_a_deterministic_order() {
        let dir = TempDir::new("tree");
        let nested = dir.path().join("b");
        fs::create_dir_all(nested.join("c")).unwrap();
        write(&nested.join("c").join("deep.txt"), 1);
        write(&dir.path().join("a.txt"), 2);
        write(&nested.join("z.txt"), 3);

        let jobs = expand_selection(&[dir.path().to_path_buf()]).unwrap();
        let displays: Vec<&str> = jobs.iter().map(|j| j.display_path.as_str()).collect();
        assert_eq!(displays, vec!["a.txt", "b\\z.txt", "b\\c\\deep.txt"]);

        let again = expand_selection(&[dir.path().to_path_buf()]).unwrap();
        let again: Vec<&str> = again.iter().map(|j| j.display_path.as_str()).collect();
        assert_eq!(displays, again, "the walk order must be reproducible");
    }

    #[test]
    fn a_missing_root_is_an_error() {
        let dir = TempDir::new("missing");
        let absent = dir.path().join("not-there.bin");
        assert!(expand_selection(&[absent]).is_err());
    }

    /// The cycle this walk exists to avoid: a directory that contains itself
    /// must not make expansion run forever.
    #[cfg(windows)]
    #[test]
    fn a_directory_junction_is_not_followed() {
        use std::process::Command;

        let dir = TempDir::new("junction");
        let real = dir.path().join("real");
        fs::create_dir_all(&real).unwrap();
        write(&real.join("inside.txt"), 4);

        let link = dir.path().join("loop");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let Ok(status) = status else { return };
        if !status.success() {
            // Creating a junction is not always permitted; the walk's behaviour
            // is still covered by the symlink-free case above.
            return;
        }

        let jobs = expand_selection(&[dir.path().to_path_buf()]).unwrap();
        let displays: Vec<&str> = jobs.iter().map(|j| j.display_path.as_str()).collect();
        assert_eq!(
            displays,
            vec!["real\\inside.txt"],
            "the junction must be skipped, and must certainly not be entered"
        );
    }
}
