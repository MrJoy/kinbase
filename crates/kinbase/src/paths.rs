//! Filesystem containment (architecture §6 and §12): content-addressed
//! sharded paths built only from computed lowercase digests, symlink and
//! root-escape rejection, restrictive modes, and atomic durable writes.

use crate::error::ContractError;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(crate) fn lock_file(path: &Path, role: &str) -> Result<fs::File, ContractError> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ContractError::io(role, error))?;
    loop {
        // SAFETY: the descriptor is owned and remains open while the lock is held.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        match std::io::Error::last_os_error() {
            error if error.kind() == std::io::ErrorKind::Interrupted => continue,
            error => return Err(ContractError::io(role, error)),
        }
    }
}

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
        fs::create_dir_all(path).map_err(|error| {
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
    fs::create_dir_all(path).map_err(|error| ContractError::io(&format!("create {role}"), error))
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
    let parent = path
        .parent()
        .ok_or_else(|| ContractError::internal("atomic write target has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| ContractError::io("create parent", error))?;
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
