//! Filesystem containment (architecture §6 and §12): content-addressed
//! sharded paths built only from computed lowercase digests, symlink and
//! root-escape rejection, restrictive modes, and atomic durable writes.

use crate::error::ContractError;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// `<hex-0:2>/<hex-2:4>/<remaining-60-hex>.json` from a verified digest.
pub fn sharded_relative(digest: &str) -> Result<PathBuf, ContractError> {
    if !crate::hash::is_sha256(digest) {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "content-addressed path requires a lowercase 64-hex SHA-256 digest",
            "Recompute the digest from canonical bytes; aliases are rejected.",
        ));
    }
    Ok(PathBuf::from(&digest[0..2])
        .join(&digest[2..4])
        .join(format!("{}.json", &digest[4..])))
}

/// Inverse of [`sharded_relative`] for a path found on disk under a store
/// root; rejects anything that is not the exact computed form.
pub fn digest_from_sharded(relative: &Path) -> Option<String> {
    let components: Vec<&str> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();
    if components.len() != 3 {
        return None;
    }
    let (first, second, rest) = (components[0], components[1], components[2]);
    let rest = rest.strip_suffix(".json")?;
    if first.len() != 2 || second.len() != 2 || rest.len() != 60 {
        return None;
    }
    let digest = format!("{first}{second}{rest}");
    crate::hash::is_sha256(&digest).then_some(digest)
}

/// Reject any component that could alias, traverse, or hide (NUL, dot
/// segments, separators, uppercase, non-ASCII).
pub fn validate_relative_component(component: &str) -> Result<(), ContractError> {
    let bad = component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.contains('\0')
        || !component.is_ascii()
        || component.bytes().any(|b| b.is_ascii_uppercase());
    if bad {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "path component is not a lowercase ASCII content address",
            "Only computed lowercase digest paths are admitted under .kin/.",
        ));
    }
    Ok(())
}

/// Ensure `candidate` lies under `root` without traversing a symlink at any
/// level below the root. Returns the joined path.
pub fn contained(root: &Path, relative: &Path) -> Result<PathBuf, ContractError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                validate_relative_component(part.to_str().unwrap_or(""))?;
                current.push(part);
                if let Ok(metadata) = fs::symlink_metadata(&current) {
                    if metadata.file_type().is_symlink() {
                        return Err(ContractError::integrity(
                            "DIGEST_MISMATCH",
                            "symlink inside a declared store root",
                            "Remove the symlink; store paths must be regular files and directories.",
                        ));
                    }
                }
            }
            _ => {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    "path escapes its declared root",
                    "Use a relative computed path under the store root.",
                ));
            }
        }
    }
    Ok(current)
}

pub fn reject_symlink(path: &Path, role: &str) -> Result<(), ContractError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("{role} is a symlink"),
                "Point at a regular directory or file; symlinks are rejected.",
            ));
        }
    }
    Ok(())
}

/// Create (if needed) a directory and force mode 0700; refuse symlinks and
/// group/other-writable existing directories that cannot be tightened.
pub fn ensure_private_dir(path: &Path, role: &str) -> Result<(), ContractError> {
    reject_symlink(path, role)?;
    if !path.exists() {
        create_dirs_like_parent(path).map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("{role} directory cannot be created ({})", error.kind()),
                format!(
                    "Make {} writable by the current user; no partial schema was created.",
                    path.display()
                ),
            )
        })?;
    }
    let metadata = fs::metadata(path).map_err(|error| ContractError::unreadable(role, &error))?;
    if !metadata.is_dir() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} path is not a directory"),
            "Point the configuration at a directory.",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            format!(
                "{role} directory mode cannot be set to 0700 ({})",
                error.kind()
            ),
            format!("Run `chmod 0700 {}` and retry.", path.display()),
        )
    })?;
    Ok(())
}

pub fn ensure_dir(path: &Path, role: &str) -> Result<(), ContractError> {
    reject_symlink(path, role)?;
    create_dirs_like_parent(path)
        .map_err(|error| ContractError::io(&format!("create {role}"), error))
}

/// `create_dir_all`, except each directory it creates takes the mode of the
/// nearest one that already exists rather than the process umask's. A shard
/// directory inside the Personal store (0700) used to be created 0755.
fn create_dirs_like_parent(path: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut existing = directory_or_cwd(path);
    while !existing.is_dir() {
        missing.push(existing);
        match existing.parent() {
            Some(parent) => existing = directory_or_cwd(parent),
            None => return fs::create_dir_all(path),
        }
    }
    let mode = fs::metadata(existing)?.permissions().mode() & 0o777;
    let mut builder = fs::DirBuilder::new();
    builder.mode(mode);
    for directory in missing.into_iter().rev() {
        match builder.create(directory) {
            // Another writer made it first; anything else standing there is
            // still refused, as `create_dir_all` refuses it.
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
            result => result?,
        }
    }
    Ok(())
}

/// A relative path's empty parent is the working directory.
fn directory_or_cwd(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

/// The group and other bits a file may keep inside a directory of
/// `directory_mode`: whoever can traverse the directory (its x bit) can open
/// the file by name, so only those classes keep their access.
fn reachable_bits(directory_mode: u32) -> u32 {
    let group = if directory_mode & 0o010 != 0 {
        0o070
    } else {
        0
    };
    let other = if directory_mode & 0o001 != 0 {
        0o007
    } else {
        0
    };
    group | other
}

/// Durable atomic write: temp file in the same directory, fsync, rename,
/// fsync directory. Never overwrites an existing content-addressed file
/// with different bytes when `immutable` is set.
pub fn write_atomic(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    immutable: bool,
) -> Result<bool, ContractError> {
    let parent = directory_or_cwd(
        path.parent()
            .ok_or_else(|| ContractError::internal("atomic write target has no parent"))?,
    );
    create_dirs_like_parent(parent).map_err(|error| ContractError::io("create parent", error))?;
    // A file never grants group or other access to anyone who cannot reach
    // it through its directory: an event written 0644 into the Personal
    // store lands 0600.
    let directory_mode = fs::metadata(parent)
        .map_err(|error| ContractError::io("read parent", error))?
        .permissions()
        .mode();
    let mode = mode & (0o700 | reachable_bits(directory_mode));
    if immutable && path.exists() {
        let existing = fs::read(path).map_err(|error| ContractError::io("read existing", error))?;
        if existing == bytes {
            return Ok(false);
        }
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "content-addressed path already holds different bytes",
            "Run full fsck; an existing event is never rewritten.",
        ));
    }
    let temp = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        crate::crypto::random_token()
    ));
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&temp)
            .map_err(|error| ContractError::io("create temp", error))?;
        std::io::Write::write_all(&mut file, bytes)
            .map_err(|error| ContractError::io("write temp", error))?;
        file.sync_all()
            .map_err(|error| ContractError::io("sync temp", error))?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(ContractError::io("rename", error));
    }
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(true)
}

pub fn read_bounded(path: &Path, limit: usize, role: &str) -> Result<Vec<u8>, ContractError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| ContractError::unreadable(role, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} is a symlink"),
            "Supply a regular file.",
        ));
    }
    if metadata.len() as usize > limit {
        return Err(ContractError::limit(
            format!("{role} exceeds the {limit}-byte ceiling"),
            serde_json::json!({"bytes": metadata.len(), "ceiling_bytes": limit, "refused_count": 1, "omitted_count": 1}),
        ));
    }
    fs::read(path).map_err(|error| ContractError::unreadable(role, &error))
}

/// Recursively list regular files under a directory in sorted order,
/// returning paths relative to `root`. Symlinks are refused.
pub fn list_files(root: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let mut output = Vec::new();
    if root.is_dir() {
        walk(root, root, &mut output)?;
    }
    output.sort();
    Ok(output)
}

fn walk(root: &Path, current: &Path, output: &mut Vec<PathBuf>) -> Result<(), ContractError> {
    // The directory entry already carries its own kind, so the walk costs one
    // `readdir` per directory rather than one `lstat` per file. The symlink
    // rejection is unchanged: an entry type is never followed.
    let mut children: Vec<(PathBuf, fs::FileType)> = Vec::new();
    for entry in
        fs::read_dir(current).map_err(|error| ContractError::io("read directory", error))?
    {
        let entry = entry.map_err(|error| ContractError::io("read directory entry", error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| ContractError::io("stat", error))?;
        children.push((entry.path(), file_type));
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));
    for (child, file_type) in children {
        if file_type.is_symlink() {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                "symlink inside a declared store root",
                "Remove the symlink; store paths must be regular files and directories.",
            ));
        }
        if file_type.is_dir() {
            walk(root, &child, output)?;
        } else if file_type.is_file() {
            output.push(child.strip_prefix(root).unwrap_or(&child).to_path_buf());
        }
    }
    Ok(())
}

/// Count regular files under `root`, stopping as soon as `cap` is exceeded.
///
/// Returns `(observed, capped)`; `capped` marks the count as a lower bound.
/// A ceiling refusal reads no event bytes and does not materialize the tree:
/// the store is refused before the work (architecture §11 ceilings).
pub fn count_files_capped(root: &Path, cap: usize) -> Result<(usize, bool), ContractError> {
    let mut observed = 0usize;
    if root.is_dir() {
        let mut stack = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            let entries = fs::read_dir(&current)
                .map_err(|error| ContractError::io("read directory", error))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| ContractError::io("read directory entry", error))?;
                let file_type = entry
                    .file_type()
                    .map_err(|error| ContractError::io("stat", error))?;
                if file_type.is_dir() {
                    stack.push(entry.path());
                } else if file_type.is_file() {
                    observed += 1;
                    if observed > cap {
                        return Ok((observed, true));
                    }
                }
            }
        }
    }
    Ok((observed, false))
}

/// Total byte length of the regular files under `root`, from directory
/// metadata only; no file content is read.
pub fn total_file_bytes(root: &Path) -> Result<u64, ContractError> {
    let mut total = 0u64;
    if root.is_dir() {
        let mut stack = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            let entries = fs::read_dir(&current)
                .map_err(|error| ContractError::io("read directory", error))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| ContractError::io("read directory entry", error))?;
                let file_type = entry
                    .file_type()
                    .map_err(|error| ContractError::io("stat", error))?;
                if file_type.is_dir() {
                    stack.push(entry.path());
                } else if file_type.is_file() {
                    total = total.saturating_add(
                        entry
                            .metadata()
                            .map_err(|error| ContractError::io("stat", error))?
                            .len(),
                    );
                }
            }
        }
    }
    Ok(total)
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

/// `${XDG_CONFIG_HOME:-~/.config}/kinbase`
pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config"))
        .join("kinbase")
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn what_is_created_under_a_private_directory_stays_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("personal");
        ensure_private_dir(&root, "test store").expect("root");
        assert_eq!(mode(&root), 0o700, "precondition: a private root");

        // An event store's shard directories, then the event itself.
        let shard = root.join("events").join("7a").join("ee");
        ensure_dir(&shard, "event store").expect("shard");
        let event = shard.join("event.json");
        write_atomic(&event, b"{}", 0o644, true).expect("event");
        // A write whose parents do not exist yet.
        let body = root.join("bodies").join("ab").join("body");
        write_atomic(&body, b"body", 0o600, false).expect("body");

        for created in [
            root.join("events"),
            root.join("events").join("7a"),
            shard.clone(),
            root.join("bodies"),
            root.join("bodies").join("ab"),
        ] {
            assert_eq!(mode(&created), 0o700, "{}", created.display());
        }
        assert_eq!(mode(&event), 0o600);
        assert_eq!(mode(&body), 0o600);
    }

    /// The process umask, read from a directory created asking for 0777.
    fn umask(dir: &Path) -> u32 {
        let probe = dir.join("umask-probe");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o777);
        builder.create(&probe).expect("probe");
        !mode(&probe) & 0o777
    }

    #[test]
    fn what_is_created_under_a_shared_directory_takes_its_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let umask = umask(dir.path());
        let root = dir.path().join("kin");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).expect("chmod");
        let event = root.join("events").join("7a").join("event.json");
        write_atomic(&event, b"{}", 0o644, true).expect("event");
        assert_eq!(mode(&root.join("events")), 0o750 & !umask);
        assert_eq!(mode(&root.join("events").join("7a")), 0o750 & !umask);
        assert_eq!(mode(&event), 0o640 & !umask);
    }

    #[test]
    fn a_file_keeps_what_its_directory_lets_a_class_reach() {
        let dir = tempfile::tempdir().expect("tempdir");
        let umask = umask(dir.path());
        // Traversable but not listable: a reader who knows the name opens it.
        let root = dir.path().join("drop");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o711)).expect("chmod");
        let file = root.join("file.json");
        write_atomic(&file, b"{}", 0o644, false).expect("file");
        assert_eq!(mode(&file), 0o644 & !umask);
    }

    #[test]
    fn ensuring_a_directory_where_a_file_stands_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("plain");
        fs::write(&file, b"x").expect("file");
        assert!(file.is_file(), "precondition");
        assert!(ensure_dir(&file, "test").is_err());
        assert!(write_atomic(&file.join("inner.json"), b"{}", 0o600, false).is_err());
    }

    #[test]
    fn a_bare_filename_resolves_to_the_working_directory() {
        // Not written here: changing this process's working directory would
        // race every other test that reads it.
        let parent = Path::new("bare.json").parent().expect("parent");
        assert_eq!(directory_or_cwd(parent), Path::new("."));
        create_dirs_like_parent(Path::new("")).expect("the working directory exists");
    }
}
