//! Process containment (architecture §1, §6; interface contract §4, C17):
//! descriptor enumeration/attestation with the platform-native facility,
//! the macOS `sandbox-exec` denial probe, and descriptor-backed classifier
//! execution.

use crate::error::ContractError;
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The frozen CLOEXEC-by-default descriptor allowlist: stdio plus any
/// explicitly declared launcher descriptors.
pub fn allowlist() -> Vec<i32> {
    let mut list = vec![0, 1, 2];
    for name in ["KINBASE_CLIENT_KEY_FD", "KINBASE_SHARED_CONFIG_FD"] {
        if let Ok(value) = std::env::var(name) {
            if let Ok(fd) = value.trim().parse::<i32>() {
                list.push(fd);
            }
        }
    }
    list
}

#[derive(Debug, Clone)]
pub struct OpenDescriptor {
    pub fd: i32,
    pub dev: u64,
    pub ino: u64,
    pub is_dir: bool,
    pub path: Option<PathBuf>,
}

/// Enumerate live descriptors with `fcntl(F_GETFD)` (never `/dev/fd`, which
/// would open a descriptor of its own) and `fstat`; on macOS `F_GETPATH`
/// resolves the path for containment checks.
pub fn open_descriptors() -> Vec<OpenDescriptor> {
    // SAFETY: sysconf and fcntl/fstat on integer descriptors have no memory
    // safety preconditions; failures are reported through return codes.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max = if max <= 0 { 1024 } else { max.min(65_536) } as i32;
    let mut output = Vec::new();
    for fd in live_descriptors(max) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            continue;
        }
        let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let path = descriptor_path(fd);
        output.push(OpenDescriptor {
            fd,
            dev: stat.st_dev as u64,
            ino: stat.st_ino,
            is_dir,
            path,
        });
    }
    output
}

/// The open descriptors below `max`, found without opening one.
///
/// On Linux, `poll` with no requested events reports `POLLNVAL` for a closed
/// descriptor and only for a closed one, whatever the open one refers to
/// (file, directory, pipe, socket, device), so one call covers 1,024 numbers.
/// Probing each number with `fcntl` took 65,536 system calls per attestation,
/// and every process attests at startup. Other systems do not promise that:
/// macOS `poll` reports `POLLNVAL` for open descriptors it cannot poll, such
/// as some devices, which would hide them from attestation. There every
/// number is probed with `fcntl`, as before.
fn live_descriptors(max: i32) -> Vec<i32> {
    if cfg!(target_os = "linux") {
        poll_live_descriptors(max)
    } else {
        probe_live_descriptors(0, max)
    }
}

fn probe_live_descriptors(start: i32, end: i32) -> Vec<i32> {
    // SAFETY: fcntl on an integer descriptor has no memory preconditions.
    (start..end)
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .collect()
}

fn poll_live_descriptors(max: i32) -> Vec<i32> {
    const BATCH: i32 = 1024;
    let mut live = Vec::new();
    let mut start = 0;
    while start < max {
        let end = (start + BATCH).min(max);
        let mut fds: Vec<libc::pollfd> = (start..end)
            .map(|fd| libc::pollfd {
                fd,
                events: 0,
                revents: 0,
            })
            .collect();
        let rc = loop {
            // SAFETY: `fds` is a live, correctly sized pollfd array; a zero
            // timeout never blocks.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
            if rc >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break rc;
            }
        };
        if rc < 0 {
            // poll refused the batch: probe it one number at a time.
            live.extend(probe_live_descriptors(start, end));
        } else {
            live.extend(fds.iter().filter(|p| p.revents & libc::POLLNVAL == 0).map(|p| p.fd));
        }
        start = end;
    }
    live
}

#[cfg(target_os = "macos")]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes into the buffer.
    let result = unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) };
    if result < 0 {
        return None;
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    Some(PathBuf::from(
        String::from_utf8_lossy(&buffer[..end]).into_owned(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

/// Device/inode of a directory, for containment comparison.
pub fn dir_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Close every inherited descriptor outside the allowlist that is not under
/// the Personal root, so the process no longer holds it. For host hooks only:
/// the host (Codex, Claude Code) is the parent, and Codex passes every hook
/// a descriptor kinbase cannot refuse at launch. A Personal descriptor stays
/// open so [`attest_descriptors`] still fails startup on it.
pub fn close_stray_descriptors(personal_root: Option<&Path>) {
    let allow = allowlist();
    let personal_identity = personal_root.and_then(dir_identity);
    let personal_canonical = personal_root.and_then(|root| root.canonicalize().ok());
    for descriptor in open_descriptors() {
        if !allow.contains(&descriptor.fd)
            && !under_personal(&descriptor, personal_identity, personal_canonical.as_deref())
        {
            // SAFETY: runs before this process wraps any descriptor in an
            // owned handle, so nothing else refers to the one closed here.
            unsafe { libc::close(descriptor.fd) };
        }
    }
}

/// Whether `descriptor` is the Personal root or resolves under it.
fn under_personal(
    descriptor: &OpenDescriptor,
    identity: Option<(u64, u64)>,
    canonical: Option<&Path>,
) -> bool {
    identity.is_some_and(|(dev, ino)| descriptor.dev == dev && descriptor.ino == ino)
        || canonical
            .zip(descriptor.path.as_ref())
            .is_some_and(|(root, path)| path.starts_with(root))
}

/// Startup attestation: refuse any inherited descriptor under the Personal
/// root (by device/inode or resolved path) and any descriptor outside the
/// frozen allowlist. Returns the attestation record for `doctor`.
pub fn attest_descriptors(personal_root: Option<&Path>) -> Result<Value, ContractError> {
    let allow = allowlist();
    let descriptors = open_descriptors();
    let personal_identity = personal_root.and_then(dir_identity);
    let personal_canonical = personal_root.and_then(|root| root.canonicalize().ok());
    let mut extra = Vec::new();
    for descriptor in &descriptors {
        if under_personal(descriptor, personal_identity, personal_canonical.as_deref()) {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("inherited descriptor {} resolves under the Personal root; shared work refused before any side effect", descriptor.fd),
                "Launch shared processes with the frozen descriptor allowlist only; never pass a Personal directory or file descriptor.",
            )
            .with_detail(json!({"shared_work_performed": false, "descriptor": descriptor.fd, "is_dir": descriptor.is_dir})));
        }
        if !allow.contains(&descriptor.fd) {
            extra.push(descriptor.fd);
        }
    }
    if !extra.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{} inherited descriptor(s) outside the frozen allowlist; shared work refused before any side effect", extra.len()),
            "Launch with only the declared descriptors (stdio plus explicit KINBASE_*_FD values).",
        )
        .with_detail(json!({"shared_work_performed": false, "descriptors": extra})));
    }
    Ok(json!({
        "allowlist": allow,
        "open_descriptors": descriptors.iter().map(|d| d.fd).collect::<Vec<_>>(),
        "personal_descriptor_present": false,
        "facility": if cfg!(target_os = "macos") { "fcntl(F_GETFD)+fstat+F_GETPATH" } else { "fcntl(F_GETFD)+fstat+/proc/self/fd" }
    }))
}

/// macOS sandbox profile denying the Personal root and all unrelated user
/// paths while allowing only the declared Company cache and one repository
/// root (plus the system toolchain paths the binary needs to run).
pub fn profile(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
) -> String {
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(allow process-exec process-fork sysctl-read mach-lookup)".to_owned(),
        "(allow file-read-metadata)".to_owned(),
        "(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/opt\") (subpath \"/private/etc\") (subpath \"/dev\") (subpath \"/private/var/db\") (literal \"/\"))".to_owned(),
        "(allow file-write-data (literal \"/dev/null\") (literal \"/dev/tty\") (regex #\"^/dev/fd/\"))".to_owned(),
        "(allow file-read* (regex #\"^/dev/fd/\"))".to_owned(),
    ];
    for root in allowed_roots {
        let quoted = root.to_string_lossy().replace('"', "\\\"");
        lines.push(format!(
            "(allow file-read* file-write* (subpath \"{quoted}\"))"
        ));
    }
    if let Some(port) = company_port {
        lines.push(format!(
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        ));
    }
    let personal = personal_root.to_string_lossy().replace('"', "\\\"");
    lines.push(format!(
        "(deny file-read* file-write* file-read-metadata (subpath \"{personal}\"))"
    ));
    lines.join("\n")
}

pub fn sandbox_available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists()
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub enforced: bool,
    pub personal_root_readable: bool,
    pub disabled_loudly: bool,
    pub detail: Value,
}

/// Run the startup denial probe: a child under the sandbox profile attempts
/// to read the Personal root. Success is a hard failure of the boundary.
pub fn denial_probe(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
) -> ProbeResult {
    if !sandbox_available() {
        return ProbeResult {
            enforced: false,
            personal_root_readable: true,
            disabled_loudly: true,
            detail: json!({"reason": "no supported kernel enforcement (sandbox-exec) on this platform; shared projection/publication disabled"}),
        };
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return ProbeResult {
                enforced: false,
                personal_root_readable: true,
                disabled_loudly: true,
                detail: json!({"reason": format!("current executable unavailable ({})", error.kind())}),
            };
        }
    };
    let profile = profile(personal_root, allowed_roots, company_port);
    let output = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg(&exe)
        .arg("__probe")
        .arg(personal_root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let readable = stdout.contains("\"readable\":true");
            let probe_ran = stdout.contains("\"probe\":\"personal-root\"");
            ProbeResult {
                enforced: probe_ran && !readable,
                personal_root_readable: readable,
                disabled_loudly: !probe_ran || readable,
                detail: json!({"probe_ran": probe_ran, "exit": output.status.code(), "readable": readable}),
            }
        }
        Err(error) => ProbeResult {
            enforced: false,
            personal_root_readable: true,
            disabled_loudly: true,
            detail: json!({"reason": format!("sandbox-exec failed to launch ({})", error.kind())}),
        },
    }
}

/// The probe child body: attempt to open and list the directory; report
/// whether any byte of the tree was readable. Never prints the path.
pub fn probe_main(target: &Path) -> i32 {
    let mut readable = false;
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            readable = true;
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(mut file) = std::fs::File::open(entry.path()) {
                        let mut buffer = [0u8; 1];
                        let _ = std::io::Read::read(&mut file, &mut buffer);
                    }
                }
            }
        }
    }
    if !readable {
        if let Ok(metadata) = std::fs::metadata(target) {
            readable = metadata.is_dir() && std::fs::read_dir(target).is_ok();
        }
    }
    println!("{{\"probe\":\"personal-root\",\"readable\":{readable}}}");
    if readable { 0 } else { 3 }
}

/// Run a shared helper under the sandbox with a scrubbed environment and the
/// shared configuration on an explicit descriptor (never argv or env).
pub fn run_shared(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
    args: &[String],
    shared_config: &[u8],
) -> Result<std::process::Output, ContractError> {
    let exe =
        std::env::current_exe().map_err(|error| ContractError::io("current executable", error))?;
    let profile = profile(personal_root, allowed_roots, company_port);
    let mut command = if sandbox_available() {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile).arg(&exe);
        command
    } else {
        return Err(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "no supported kernel enforcement is available; shared projection/publication is disabled",
            "Run on macOS with sandbox-exec (or a Landlock/bubblewrap backend) to enable shared work.",
        ));
    };
    let (mut reader, mut writer) = pipe()?;
    let reader_fd = reader.as_raw_fd();
    clear_cloexec(reader_fd)?;
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
        .env("HOME", "/nonexistent")
        .env("KINBASE_SHARED_CONFIG_FD", reader_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .map_err(|error| ContractError::io("spawn shared helper", error))?;
    std::io::Write::write_all(&mut writer, shared_config)
        .map_err(|error| ContractError::io("write shared config", error))?;
    drop(writer);
    let output = child
        .wait_with_output()
        .map_err(|error| ContractError::io("wait shared helper", error))?;
    let _ = std::io::Read::read(&mut reader, &mut [0u8; 1]);
    Ok(output)
}

fn pipe() -> Result<(std::fs::File, std::fs::File), ContractError> {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: pipe writes two descriptors into the array on success.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(ContractError::io("pipe", std::io::Error::last_os_error()));
    }
    for fd in fds {
        // SAFETY: setting CLOEXEC on descriptors we own.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    // SAFETY: the descriptors are fresh and owned by this process.
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    })
}

fn clear_cloexec(fd: i32) -> Result<(), ContractError> {
    // SAFETY: clearing CLOEXEC on a descriptor we own so one child inherits it.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(ContractError::io(
            "clear cloexec",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// An executable opened once and verified through that descriptor.
struct VerifiedExecutable {
    file: std::fs::File,
    metadata: std::fs::Metadata,
}

/// What verifying a pinned executable found: the digest it read, when it got
/// that far, and the rule that refused the executable, if any. These are the
/// checks `run_verified_executable` makes before it runs anything.
pub struct PinnedCheck {
    pub observed_sha256: Option<String>,
    pub refusal: Option<ContractError>,
}

pub fn check_pinned_executable(executable: &Path, expected_sha256: &str) -> PinnedCheck {
    match open_verified(executable, expected_sha256) {
        Ok((_, observed)) => PinnedCheck {
            observed_sha256: Some(observed),
            refusal: None,
        },
        Err((observed, error)) => PinnedCheck {
            observed_sha256: observed,
            refusal: Some(error),
        },
    }
}

/// Open the absolute executable once and verify owner, mode, regular file,
/// the containing directory chain and the pinned SHA-256 through that
/// descriptor. A refusal carries the digest when it was read.
fn open_verified(
    executable: &Path,
    expected_sha256: &str,
) -> Result<(VerifiedExecutable, String), (Option<String>, ContractError)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let refuse = |error: ContractError| (None, error);
    if !executable.is_absolute() {
        return Err(refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable must be an absolute path",
            "Configure an absolute regular-file path; no PATH or shell resolution exists.",
        )));
    }
    let file = std::fs::File::open(executable).map_err(|error| {
        refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            format!("classifier executable cannot be opened ({})", error.kind()),
            "Configure a readable absolute executable.",
        ))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| refuse(ContractError::io("fstat classifier", error)))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != euid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable is not a regular file owned by the effective user without group/other write",
            "Fix ownership and mode of the classifier executable.",
        )));
    }
    let mut ancestor = executable.parent();
    while let Some(dir) = ancestor {
        if let Ok(dir_metadata) = std::fs::symlink_metadata(dir) {
            if dir_metadata.file_type().is_symlink() {
                return Err(refuse(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier containing-directory chain traverses a symlink",
                    "Place the classifier under a symlink-free directory chain.",
                )));
            }
            if dir_metadata.permissions().mode() & 0o022 != 0 && dir != Path::new("/") {
                return Err(refuse(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier containing directory is writable by group or other",
                    "Tighten the directory chain to 0755 or stricter.",
                )));
            }
        }
        ancestor = dir.parent();
    }
    let mut bytes = Vec::new();
    {
        let mut reader = &file;
        std::io::Read::read_to_end(&mut reader, &mut bytes)
            .map_err(|error| refuse(ContractError::io("read classifier", error)))?;
    }
    let observed = crate::hash::sha256_bytes(&bytes);
    if observed != expected_sha256 {
        // A rebuilt classifier stops every classification until it is
        // re-pinned; say what was read and how to pin it.
        let error = ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable digest differs from the pinned SHA-256",
            "Review the executable, then record its digest (`shasum -a 256` of the configured \
             path; `kinbase doctor` shows it as classifier.observed_sha256) as \
             classifier.executable_sha256 in a reviewed configuration change; no input was sent.",
        )
        .with_detail(json!({
            "pinned_sha256": expected_sha256,
            "observed_sha256": observed
        }));
        return Err((Some(observed), error));
    }
    Ok((VerifiedExecutable { file, metadata }, observed))
}

/// The most classifier stdout kept (the input bound).
pub const MAX_CLASSIFIER_OUTPUT: usize = 8 * 1024 * 1024;
/// The most classifier stderr kept; its first line is reported.
const MAX_CLASSIFIER_STDERR: usize = 64 * 1024;
/// How long output may keep arriving after the classifier exits.
const OUTPUT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// One child pipe, read without blocking on the calling thread, keeping at
/// most `limit` bytes (the rest is read and discarded, so the writer never
/// blocks on a full pipe). The descriptor closes when the pipe ends or the
/// capture is dropped.
struct Capture {
    pipe: Option<std::fs::File>,
    kept: Vec<u8>,
    limit: usize,
    over: bool,
}

impl Capture {
    fn new(pipe: Option<std::os::fd::OwnedFd>, limit: usize) -> std::io::Result<Self> {
        let pipe = pipe.map(std::fs::File::from);
        if let Some(pipe) = &pipe {
            set_nonblocking(pipe.as_raw_fd())?;
        }
        Ok(Self {
            pipe,
            kept: Vec::new(),
            limit,
            over: false,
        })
    }

    fn fd(&self) -> Option<i32> {
        self.pipe.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Read whatever is available now.
    fn drain(&mut self) {
        let Some(pipe) = self.pipe.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match std::io::Read::read(pipe, &mut chunk) {
                Ok(0) => {
                    self.pipe = None;
                    return;
                }
                Ok(read) => {
                    let room = self.limit.saturating_sub(self.kept.len());
                    self.over |= read > room;
                    self.kept.extend_from_slice(&chunk[..read.min(room)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.pipe = None;
                    return;
                }
            }
        }
    }
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    // SAFETY: fcntl on a descriptor this process owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Descriptor-backed classifier execution (architecture §5): open the
/// absolute executable once, verify owner/mode/regular file/containing
/// directory chain and the pinned SHA-256 through that descriptor, then
/// execute `/dev/fd/N` (the descriptor itself; the pathname is never
/// re-resolved). Returns stdout bytes.
pub fn run_verified_executable(
    executable: &Path,
    expected_sha256: &str,
    args: &[String],
    input: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ContractError> {
    run_verified_executable_with_env(executable, expected_sha256, args, &[], input, timeout)
}

/// As `run_verified_executable`, with these variables added to the scrubbed
/// environment (named by configuration, such as a provider key).
pub fn run_verified_executable_with_env(
    executable: &Path,
    expected_sha256: &str,
    args: &[String],
    env: &[(String, String)],
    input: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ContractError> {
    use std::os::unix::fs::MetadataExt;
    let (VerifiedExecutable { file, metadata }, _) =
        open_verified(executable, expected_sha256).map_err(|(_, error)| error)?;
    let fd = file.as_raw_fd();
    // The verified descriptor is exposed to exactly this child: CLOEXEC stays
    // set in the parent and is cleared after fork, so a concurrently spawned
    // sibling never inherits another child's descriptor (which its own
    // startup attestation would rightly refuse).
    let inherit_verified_descriptor = move || -> std::io::Result<()> {
        // SAFETY: fcntl is async-signal-safe and the descriptor is ours.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    let program = format!("/dev/fd/{fd}");
    let mut command = Command::new(&program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("KINBASE_SHARED_CONFIG_FD", fd.to_string())
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Its own process group, so a timeout reaches everything it started.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    // SAFETY: the hook only calls fcntl, which is async-signal-safe.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut command, inherit_verified_descriptor);
    }
    let spawn = command.spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) =>
        {
            // Darwin does not permit executing a regular file through /dev/fd.
            // The descriptor above still performed ownership/mode/digest pinning;
            // refuse to fall back unless the pathname still names the same inode.
            let fallback = std::fs::File::open(executable)
                .map_err(|error| ContractError::io("reopen classifier", error))?;
            let fallback_metadata = fallback
                .metadata()
                .map_err(|error| ContractError::io("fstat classifier", error))?;
            if fallback_metadata.dev() != metadata.dev()
                || fallback_metadata.ino() != metadata.ino()
            {
                return Err(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier pathname changed after descriptor verification",
                    "Repin the classifier digest; the changed executable was not run.",
                ));
            }
            let mut fallback_command = Command::new(executable);
            fallback_command
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("KINBASE_SHARED_CONFIG_FD", fd.to_string())
                .envs(env.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            std::os::unix::process::CommandExt::process_group(&mut fallback_command, 0);
            // SAFETY: the hook only calls fcntl, which is async-signal-safe.
            unsafe {
                std::os::unix::process::CommandExt::pre_exec(
                    &mut fallback_command,
                    inherit_verified_descriptor,
                );
            }
            fallback_command
                .spawn()
                .map_err(|error| ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("descriptor-backed execution failed ({})", error.kind()), "A platform without verified descriptor-backed execution disables the external classifier."))?
        }
        Err(error) => {
            return Err(ContractError::integrity(
                "PROCESSOR_UNAUTHORIZED",
                format!("descriptor-backed execution failed ({})", error.kind()),
                "A platform without verified descriptor-backed execution disables the external classifier.",
            ));
        }
    };
    // The input is written and both outputs read with poll on this thread,
    // against deadlines: a descendant that keeps a pipe open after the
    // classifier exits (or is killed) is never waited on past them, no
    // thread outlives the call, and every descriptor is closed when it
    // returns. Writing all input first would deadlock a classifier that
    // fills its output before reading it.
    let io_error = |error| ContractError::io("classifier pipes", error);
    let mut stdin = match child.stdin.take() {
        Some(pipe) if !input.is_empty() => {
            let pipe = std::fs::File::from(std::os::fd::OwnedFd::from(pipe));
            set_nonblocking(pipe.as_raw_fd()).map_err(io_error)?;
            Some(pipe)
        }
        _ => None,
    };
    let mut written = 0usize;
    let mut stdout = Capture::new(
        child.stdout.take().map(std::os::fd::OwnedFd::from),
        MAX_CLASSIFIER_OUTPUT,
    )
    .map_err(io_error)?;
    let mut stderr = Capture::new(
        child.stderr.take().map(std::os::fd::OwnedFd::from),
        MAX_CLASSIFIER_STDERR,
    )
    .map_err(io_error)?;
    let group = child.id() as libc::pid_t;
    let started = std::time::Instant::now();
    let mut status = None;
    let mut exited_at: Option<std::time::Instant> = None;
    let mut late = false;
    loop {
        if status.is_none() {
            // Peek at the exit without reaping: while the exited child is an
            // unreaped zombie its process-group id cannot be reused, so the
            // group can be signalled safely before the child is collected.
            // SAFETY: waitid writes only into `info`, a zeroed siginfo_t.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let peeked = unsafe {
                libc::waitid(
                    libc::P_PID,
                    group as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if peeked != 0 {
                return Err(ContractError::io(
                    "wait classifier",
                    std::io::Error::last_os_error(),
                ));
            }
            // SAFETY: si_pid is set by waitid (zero while the child runs).
            if unsafe { info.si_pid() } != 0 {
                // What the classifier left running in its group goes with it.
                // SAFETY: killpg only signals our child's (unreaped) group.
                unsafe {
                    libc::killpg(group, libc::SIGKILL);
                }
                status = Some(
                    child
                        .wait()
                        .map_err(|error| ContractError::io("wait classifier", error))?,
                );
                exited_at = Some(std::time::Instant::now());
                stdin = None;
            } else if started.elapsed() > timeout {
                // SAFETY: killpg only signals our child's (unreaped) group.
                unsafe {
                    libc::killpg(group, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(ContractError::degraded(
                    "UNKNOWN_OWNER_UNRESOLVED",
                    "classifier exceeded its wall timeout; extraction abstained",
                    "Increase classifier.timeout_seconds or use a faster local processor.",
                ));
            }
        }
        if status.is_some() && stdout.pipe.is_none() && stderr.pipe.is_none() {
            break;
        }
        if exited_at.is_some_and(|at| at.elapsed() > OUTPUT_GRACE) {
            late = stdout.pipe.is_some();
            break;
        }
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(3);
        if let Some(pipe) = &stdin {
            fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        for fd in [stdout.fd(), stderr.fd()].into_iter().flatten() {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        // SAFETY: `fds` is a live, correctly sized pollfd array.
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20);
        }
        if let Some(pipe) = stdin.as_mut() {
            match std::io::Write::write(pipe, &input[written..]) {
                Ok(count) => {
                    written += count;
                    if written >= input.len() {
                        // Closing stdin tells the classifier the input ended.
                        stdin = None;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => stdin = None,
            }
        }
        stdout.drain();
        stderr.drain();
    }
    drop(stdin);
    let status = status.ok_or_else(|| ContractError::internal("classifier status missing"))?;
    if stdout.over {
        return Err(ContractError::limit(
            format!(
                "classifier output exceeds the {MAX_CLASSIFIER_OUTPUT}-byte bound; extraction abstained"
            ),
            serde_json::json!({"refused_count": 1, "omitted_count": 1, "ceiling_bytes": MAX_CLASSIFIER_OUTPUT}),
        ));
    }
    if late {
        return Err(ContractError::degraded(
            "UNKNOWN_OWNER_UNRESOLVED",
            "classifier output did not close after it exited; extraction abstained",
            "Repair the classifier so its output ends when it does.",
        ));
    }
    let stdout = stdout.kept;
    let stderr_truncated = stderr.over;
    let stderr = stderr.kept;
    if !status.success() {
        // The child's own words travel with the failure. An exit status alone
        // cannot tell a provider pushing back from a malformed answer, and the
        // caller decides whether to wait or to retry on exactly that.
        let excerpt: String = String::from_utf8_lossy(&stderr)
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default()
            .chars()
            .take(240)
            .collect();
        return Err(ContractError::degraded(
            "UNKNOWN_OWNER_UNRESOLVED",
            // A long stderr keeps its first bytes, and says it was cut.
            match (excerpt.is_empty(), stderr_truncated) {
                (true, _) => format!("classifier exited with {status}; extraction abstained"),
                (false, false) => {
                    format!("classifier exited with {status}: {excerpt}; extraction abstained")
                }
                (false, true) => format!(
                    "classifier exited with {status}: {excerpt} (stderr truncated); extraction abstained"
                ),
            },
            "Repair the classifier; abstention creates a private Unknown.",
        ));
    }
    Ok(stdout)
}

#[cfg(test)]
mod pinned_check_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A directory whose whole chain the verifier accepts (no symlink, no
    /// group/other-writable ancestor); `/tmp` itself is 1777. An explicit
    /// `KINBASE_TEST_VERIFIED_DIR` is tried first.
    fn accepted_base() -> PathBuf {
        let candidates: Vec<PathBuf> = [
            std::env::var_os("KINBASE_TEST_VERIFIED_DIR").map(PathBuf::from),
            Some(std::env::temp_dir()),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        ]
        .into_iter()
        .flatten()
        .collect();
        candidates
            .iter()
            .filter_map(|dir| dir.canonicalize().ok())
            .find(|dir| {
                dir.ancestors().all(|ancestor| {
                    std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                        ancestor == Path::new("/")
                            || (!metadata.file_type().is_symlink()
                                && metadata.permissions().mode() & 0o022 == 0)
                    })
                })
            })
            .unwrap_or_else(|| {
                panic!(
                    "no directory chain the classifier verifier accepts among {candidates:?}; \
                     set KINBASE_TEST_VERIFIED_DIR to one"
                )
            })
    }

    #[test]
    fn a_rebuilt_executable_is_refused_with_the_digest_it_now_has() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let executable = dir.path().join("classifier");
        let body = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&executable, body).expect("write");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let digest = crate::hash::sha256_bytes(body);

        let pinned = check_pinned_executable(&executable, &digest);
        assert!(
            pinned.refusal.is_none(),
            "{:?}",
            pinned.refusal.map(|error| error.message)
        );
        assert_eq!(pinned.observed_sha256.as_deref(), Some(digest.as_str()));

        let rebuilt = check_pinned_executable(&executable, &"0".repeat(64));
        assert_eq!(rebuilt.observed_sha256.as_deref(), Some(digest.as_str()));
        let error = rebuilt.refusal.expect("a stale pin is refused");
        assert_eq!(error.code, "PROCESSOR_UNAUTHORIZED");
        assert_eq!(
            error
                .detail
                .as_ref()
                .and_then(|detail| detail["observed_sha256"].as_str()),
            Some(digest.as_str())
        );
        assert!(
            error.remediation.contains("shasum -a 256"),
            "{}",
            error.remediation
        );

        let relative = check_pinned_executable(Path::new("classifier"), &digest);
        assert!(relative.refusal.is_some());
        assert!(relative.observed_sha256.is_none());
    }

    fn pinned_script(dir: &Path, body: &str) -> (PathBuf, String) {
        let executable = dir.join("classifier");
        std::fs::write(&executable, body).expect("write");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        (executable, crate::hash::sha256_bytes(body.as_bytes()))
    }

    #[test]
    fn a_timeout_ends_a_classifier_whose_child_holds_its_output() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        // The classifier starts a long-lived child that inherits stdout,
        // then hangs; before, the wall timeout killed only the classifier
        // and then waited on the pipe the child still held.
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
sleep 30 &
sleep 30
",
        );
        let started = std::time::Instant::now();
        let error = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_millis(300),
        )
        .expect_err("timed out");
        assert!(error.message.contains("wall timeout"), "{}", error.message);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn classifier_output_is_bounded() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
head -c 9000000 /dev/zero
",
        );
        let error = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        )
        .expect_err("over the bound");
        assert_eq!(error.code, "LIMIT_EXCEEDED");

        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
printf ok
",
        );
        let output = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        )
        .expect("small output");
        assert_eq!(output, b"ok");
    }

    #[test]
    fn a_long_stderr_keeps_its_first_line() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh\necho 'provider refused: rate limited' >&2\nhead -c 200000 /dev/zero | tr '\\0' x >&2\nexit 3\n",
        );
        let error = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        )
        .expect_err("failed");
        assert!(
            error.message.contains("provider refused: rate limited"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("stderr truncated"),
            "{}",
            error.message
        );
    }

    #[test]
    fn input_larger_than_a_pipe_reaches_a_classifier_that_answers_as_it_reads() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let (executable, digest) = pinned_script(dir.path(), "#!/bin/sh\ncat\n");
        let input = vec![b'y'; 1024 * 1024];
        let output = run_verified_executable(
            &executable,
            &digest,
            &[],
            &input,
            std::time::Duration::from_secs(20),
        )
        .expect("echoed");
        assert_eq!(output, input);
    }

    #[test]
    fn an_exited_classifier_does_not_wait_on_a_detached_descendant() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        // A descendant in its own session keeps the output pipe open after
        // the classifier exits; the run ends within the grace period.
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
printf done
( trap '' HUP; exec perl -e 'use POSIX; POSIX::setsid(); sleep 30' ) &
exit 0
",
        );
        let started = std::time::Instant::now();
        let result = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        match result {
            Ok(output) => assert_eq!(output, b"done"),
            Err(error) => assert!(error.message.contains("did not close"), "{}", error.message),
        }
    }
}

#[cfg(test)]
mod descriptor_enumeration_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// The first of the descriptor numbers these tests pin: high enough that
    /// nothing else in the test process uses them, and below the soft
    /// RLIMIT_NOFILE (1,024 on many systems), where dup2 would fail.
    fn slot(offset: i32) -> i32 {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit writes into the struct it is given.
        let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            limit.rlim_cur.min(65_536) as i32
        } else {
            1_024
        };
        (soft - 80).min(3_901) + offset
    }

    /// The enumerations attestation can use: `poll` only on Linux, the one
    /// system where it never reports an open descriptor as closed.
    fn enumerations() -> Vec<fn(i32) -> Vec<i32>> {
        if cfg!(target_os = "linux") {
            vec![live_descriptors, poll_live_descriptors]
        } else {
            vec![live_descriptors]
        }
    }

    /// Tests run in parallel threads that open and close descriptors, so each
    /// case pins its descriptor at a high number nothing else uses, and the
    /// numbers around it, which nothing opens, must read as closed.
    fn check(kind: &str, fd: i32, high: i32) {
        // SAFETY: dup2 onto a descriptor number only this test uses; closed below.
        assert_eq!(unsafe { libc::dup2(fd, high) }, high, "{kind}: dup2");
        for enumerate in enumerations() {
            let live = enumerate(high + 8);
            assert!(live.contains(&high), "{kind}: open descriptor {high} not listed");
            assert!(!live.contains(&(high + 1)), "{kind}: closed descriptor {} listed", high + 1);
        }
        assert_eq!(probe_live_descriptors(high, high + 2), vec![high], "{kind}: fcntl ground truth");
        // SAFETY: closing the descriptor dup2 created.
        unsafe { libc::close(high) };
        for enumerate in enumerations() {
            assert!(!enumerate(high + 8).contains(&high), "{kind}: closed descriptor {high} listed");
        }
    }

    #[test]
    fn enumeration_sees_open_files_directories_pipes_sockets_and_devices() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("f")).unwrap();
        check("file", file.as_raw_fd(), slot(0));
        let directory = std::fs::File::open(dir.path()).unwrap();
        check("directory", directory.as_raw_fd(), slot(10));
        let mut pipe = [0i32; 2];
        // SAFETY: pipe writes two descriptors into the array.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        check("pipe read end", pipe[0], slot(20));
        check("pipe write end", pipe[1], slot(30));
        // SAFETY: closing the pipe's own descriptors.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        check("socket", left.as_raw_fd(), slot(40));
        drop(right);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        check("listening socket", listener.as_raw_fd(), slot(50));
        let device = std::fs::File::open("/dev/null").unwrap();
        check("device", device.as_raw_fd(), slot(60));
    }

    #[test]
    fn enumeration_matches_fcntl_over_the_low_range() {
        // Descriptors 0..64 move as other tests run; compare the two methods
        // on numbers that are stable for the duration: stdin, stdout, stderr.
        let probed = probe_live_descriptors(0, 3);
        for enumerate in enumerations() {
            assert_eq!(enumerate(3), probed);
        }
    }
}
