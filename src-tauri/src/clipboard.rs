use crate::input::{self, EnigoState};
#[cfg(target_os = "linux")]
use crate::settings::TypingTool;
use crate::settings::{get_settings, AutoSubmitKey, ClipboardHandling, PasteMethod};
use enigo::{Direction, Enigo, Key, Keyboard};
use log::info;
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, ExitStatus},
    sync::{Arc, LazyLock, OnceLock},
    time::Instant,
};
use tauri::{AppHandle, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;

#[cfg(target_os = "linux")]
use crate::utils::{is_gnome_wayland, is_kde_wayland, is_wayland};

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct TrustedExecutable {
    file: Arc<File>,
    identity: ExecutableIdentity,
    trusted_owner: u32,
    proc_path: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    uid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[cfg(target_os = "linux")]
impl ExecutableIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Option<Self> {
        Self::from_metadata_for_owner(metadata, 0)
    }

    fn from_metadata_for_owner(metadata: &fs::Metadata, owner: u32) -> Option<Self> {
        let mode = metadata.mode();
        if !metadata.is_file() || metadata.uid() != owner || mode & 0o111 == 0 || mode & 0o022 != 0
        {
            return None;
        }
        Some(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            uid: metadata.uid(),
            mode,
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

#[cfg(target_os = "linux")]
impl TrustedExecutable {
    pub(crate) fn resolve(name: &str) -> Option<Self> {
        if name.is_empty() || name.contains('/') {
            return None;
        }
        let path = std::env::var_os("PATH")?;
        Self::resolve_in_paths(name, std::env::split_paths(&path))
    }

    fn resolve_in_paths(
        name: &str,
        directories: impl IntoIterator<Item = PathBuf>,
    ) -> Option<Self> {
        for directory in directories {
            let Ok(directory) = fs::canonicalize(directory) else {
                continue;
            };
            if !directory.is_absolute() || !trusted_directory_chain(&directory) {
                continue;
            }
            if let Ok(executable) = Self::open(&directory.join(name)) {
                return Some(executable);
            }
        }
        None
    }

    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let supplied_metadata = fs::symlink_metadata(path)?;
        if supplied_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable symlink rejected",
            ));
        }
        let path = path
            .canonicalize()
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "untrusted executable"))?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !path.parent().is_some_and(trusted_directory_chain)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted executable provenance",
            ));
        }
        let expected = ExecutableIdentity::from_metadata(&metadata).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted executable owner or mode",
            )
        })?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        if ExecutableIdentity::from_metadata(&file.metadata()?) != Some(expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable changed while opening",
            ));
        }
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Ok(Self {
            file: Arc::new(file),
            identity: expected,
            trusted_owner: 0,
            proc_path,
        })
    }

    #[cfg(test)]
    fn open_for_test(path: &Path) -> io::Result<Self> {
        let supplied_metadata = fs::symlink_metadata(path)?;
        if supplied_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable symlink rejected",
            ));
        }
        let path = path.canonicalize()?;
        let metadata = fs::symlink_metadata(&path)?;
        let owner = unsafe { libc::geteuid() };
        let expected =
            ExecutableIdentity::from_metadata_for_owner(&metadata, owner).ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "unsafe test executable")
            })?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        if ExecutableIdentity::from_metadata_for_owner(&file.metadata()?, owner) != Some(expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test executable changed while opening",
            ));
        }
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Ok(Self {
            file: Arc::new(file),
            identity: expected,
            trusted_owner: owner,
            proc_path,
        })
    }
    pub(crate) fn is_unchanged(&self) -> bool {
        self.file.metadata().ok().and_then(|metadata| {
            ExecutableIdentity::from_metadata_for_owner(&metadata, self.trusted_owner)
        }) == Some(self.identity)
    }

    pub(crate) fn command(&self) -> io::Result<Command> {
        if !self.is_unchanged() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pinned executable changed",
            ));
        }
        let fd = self.file.as_raw_fd();
        let mut command = Command::new(&self.proc_path);
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command)
    }
}

#[cfg(target_os = "linux")]
fn trusted_directory_chain(path: &Path) -> bool {
    let mut current = Some(path);
    while let Some(directory) = current {
        let Ok(metadata) = fs::symlink_metadata(directory) else {
            return false;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return false;
        }
        current = directory.parent();
    }
    true
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kill_and_reap(mut child: Child, process_group: i32) {
    if process_group > 0 {
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let reap_deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < reap_deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    reap_child_later(child);
}

#[cfg(target_os = "linux")]
pub(crate) fn reap_child_later(child: Child) {
    static REAPER: LazyLock<std::sync::mpsc::SyncSender<Child>> = LazyLock::new(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(64);
        let _ = std::thread::Builder::new()
            .name("trusted-helper-reaper".to_owned())
            .spawn(move || {
                let mut pending: Vec<Child> = Vec::new();
                loop {
                    if pending.len() < 64 {
                        match receiver.recv_timeout(Duration::from_millis(10)) {
                            Ok(child) => pending.push(child),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                                if pending.is_empty() =>
                            {
                                return;
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                    } else {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    while pending.len() < 64 {
                        let Ok(child) = receiver.try_recv() else {
                            break;
                        };
                        pending.push(child);
                    }
                    let mut index = 0;
                    while index < pending.len() {
                        let finished = !matches!(pending[index].try_wait(), Ok(None));
                        if finished {
                            let mut child = pending.swap_remove(index);
                            let _ = child.wait();
                        } else {
                            index += 1;
                        }
                    }
                }
            });
        sender
    });
    if let Err(error) = REAPER.try_send(child) {
        let mut child = match error {
            std::sync::mpsc::TrySendError::Full(child)
            | std::sync::mpsc::TrySendError::Disconnected(child) => child,
        };
        let _ = child.wait();
    }
}

#[cfg(target_os = "linux")]
fn run_trusted(
    executable: &TrustedExecutable,
    args: &[&str],
    input: &[u8],
    limit: Duration,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + limit;
    let mut command = executable.command()?;
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let process_group = match i32::try_from(child.id()) {
        Ok(pid) => pid,
        Err(_) => {
            kill_and_reap(child, 0);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "child pid"));
        }
    };
    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            kill_and_reap(child, process_group);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "missing child stdin",
            ));
        }
    };
    if let Err(error) = set_nonblocking(stdin.as_raw_fd()) {
        drop(stdin);
        kill_and_reap(child, process_group);
        return Err(error);
    }
    let mut written = 0;
    while written < input.len() {
        if Instant::now() >= deadline {
            kill_and_reap(child, process_group);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "helper timed out"));
        }
        match stdin.write(&input[written..]) {
            Ok(0) => {
                kill_and_reap(child, process_group);
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "helper closed stdin",
                ));
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                kill_and_reap(child, process_group);
                return Err(error);
            }
        }
    }
    drop(stdin);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                unsafe {
                    libc::kill(-process_group, libc::SIGKILL);
                }
                return Ok(status);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                kill_and_reap(child, process_group);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "helper timed out"));
            }
            Err(error) => {
                kill_and_reap(child, process_group);
                return Err(error);
            }
        }
    }
}

fn with_enigo<T>(
    app_handle: &AppHandle,
    f: impl FnOnce(&mut Enigo) -> Result<T, String>,
) -> Result<T, String> {
    let enigo_state = app_handle
        .try_state::<EnigoState>()
        .ok_or("Enigo state not initialized")?;
    let mut enigo = enigo_state
        .0
        .lock()
        .map_err(|e| format!("Failed to lock Enigo: {}", e))?;
    f(&mut enigo)
}

fn write_text_to_clipboard(app_handle: &AppHandle, text: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if is_wayland() && is_wl_copy_available() {
        info!("Using wl-copy for clipboard write on Wayland");
        return write_clipboard_via_wl_copy(text);
    }

    app_handle
        .clipboard()
        .write_text(text)
        .map_err(|e| format!("Failed to write to clipboard: {}", e))
}

fn copy_text_with<T>(
    text: &str,
    write: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    write(text)
}

/// Writes final focused-output text to the clipboard without synthesizing any
/// keyboard or pointer input.
pub(crate) fn copy_text_to_clipboard(app_handle: &AppHandle, text: &str) -> Result<(), String> {
    copy_text_with(text, |text| write_text_to_clipboard(app_handle, text))
}

fn finish_clipboard_paste(
    paste_result: Result<(), String>,
    paste_delay_after_ms: u64,
    restore_clipboard: impl FnOnce(),
) -> Result<(), String> {
    std::thread::sleep(Duration::from_millis(paste_delay_after_ms));
    restore_clipboard();
    paste_result
}

/// Pastes text using the clipboard: saves current content, writes text, sends paste keystroke, restores clipboard.
fn paste_via_clipboard(
    text: &str,
    app_handle: &AppHandle,
    paste_method: &PasteMethod,
    paste_delay_ms: u64,
    paste_delay_after_ms: u64,
) -> Result<(), String> {
    let clipboard = app_handle.clipboard();
    let saved_text = clipboard.read_text().ok().filter(|t| !t.is_empty());
    // Only probe for an image when there is no text to restore. Text is by far the
    // common case, and reading an image decodes the full bitmap, so this keeps the
    // text path exactly as cheap as it was before.
    let saved_image = if saved_text.is_none() {
        clipboard.read_image().ok().map(|image| image.to_owned())
    } else {
        None
    };

    // Write text to clipboard first
    write_text_to_clipboard(app_handle, text)?;

    std::thread::sleep(Duration::from_millis(paste_delay_ms));

    // Capture key injection errors so the original clipboard is restored before
    // propagating them to the caller.
    let paste_result = (|| -> Result<(), String> {
        // Send paste key combo
        #[cfg(target_os = "linux")]
        let key_combo_sent = try_send_key_combo_linux(paste_method)?;

        #[cfg(not(target_os = "linux"))]
        let key_combo_sent = false;

        // Fall back to enigo if no native tool handled it
        if !key_combo_sent {
            with_enigo(app_handle, |enigo| match paste_method {
                // The legacy path cannot detect a mistimed chord, so it keeps the
                // conservative 100ms modifier hold.
                PasteMethod::CtrlV => input::send_paste_ctrl_v(enigo, 100),
                PasteMethod::CtrlShiftV => input::send_paste_ctrl_shift_v(enigo, 100),
                PasteMethod::ShiftInsert => input::send_paste_shift_insert(enigo, 100),
                _ => Err("Invalid paste method for clipboard paste".into()),
            })?;
        }

        Ok(())
    })();

    finish_clipboard_paste(paste_result, paste_delay_after_ms, || {
        // Restore original clipboard content even when key injection failed.
        // Text takes priority so this path stays identical to the previous behavior;
        // an image is only restored when the clipboard held no text at all, which is
        // the case that used to silently wipe screenshots.
        if let Some(clipboard_content) = saved_text {
            let _ = write_text_to_clipboard(app_handle, &clipboard_content);
        } else if let Some(image) = saved_image {
            info!("Restoring image to clipboard");
            let _ = clipboard.write_image(&image);
        } else {
            // Nothing was there to begin with — don't leave the transcription behind.
            let _ = clipboard.clear();
        }
    })
}

/// Attempts to send a key combination using Linux-native tools.
/// Returns `Ok(true)` if a native tool handled it, `Ok(false)` to fall back to enigo.
#[cfg(target_os = "linux")]
fn try_send_key_combo_linux(paste_method: &PasteMethod) -> Result<bool, String> {
    if is_wayland() {
        // Wayland: prefer wtype (but not on KDE or GNOME), then dotool, then ydotool
        // Note: wtype doesn't work on KDE (no zwp_virtual_keyboard_manager_v1 support)
        // or on GNOME/Mutter (same reason — Mutter deliberately does not implement
        // the virtual-keyboard-v1 protocol).
        if !is_kde_wayland() && !is_gnome_wayland() && is_wtype_available() {
            info!("Using wtype for key combo");
            send_key_combo_via_wtype(paste_method)?;
            return Ok(true);
        }
        if is_dotool_available() {
            info!("Using dotool for key combo");
            send_key_combo_via_dotool(paste_method)?;
            return Ok(true);
        }
        if is_ydotool_available() {
            info!("Using ydotool for key combo");
            send_key_combo_via_ydotool(paste_method)?;
            return Ok(true);
        }
    } else {
        // X11: prefer xdotool, then ydotool
        if is_xdotool_available() {
            info!("Using xdotool for key combo");
            send_key_combo_via_xdotool(paste_method)?;
            return Ok(true);
        }
        if is_ydotool_available() {
            info!("Using ydotool for key combo");
            send_key_combo_via_ydotool(paste_method)?;
            return Ok(true);
        }
    }

    Ok(false)
}

/// Attempts to type text directly using Linux-native tools.
/// Returns `Ok(true)` if a native tool handled it, `Ok(false)` to fall back to enigo.
#[cfg(target_os = "linux")]
fn try_direct_typing_linux(text: &str, preferred_tool: TypingTool) -> Result<bool, String> {
    if preferred_tool != TypingTool::Auto {
        return match preferred_tool {
            TypingTool::Wtype if is_wtype_available() => {
                info!("Using user-specified wtype");
                type_text_via_wtype(text)?;
                Ok(true)
            }
            TypingTool::Kwtype if is_kwtype_available() => {
                info!("Using user-specified kwtype");
                type_text_via_kwtype(text)?;
                Ok(true)
            }
            TypingTool::Dotool if is_dotool_available() => {
                info!("Using user-specified dotool");
                type_text_via_dotool(text)?;
                Ok(true)
            }
            TypingTool::Ydotool if is_ydotool_available() => {
                info!("Using user-specified ydotool");
                type_text_via_ydotool(text)?;
                Ok(true)
            }
            TypingTool::Xdotool if is_xdotool_available() => {
                info!("Using user-specified xdotool");
                type_text_via_xdotool(text)?;
                Ok(true)
            }
            _ => Err(format!(
                "Typing tool {:?} is not available on this system",
                preferred_tool
            )),
        };
    }

    if is_wayland() {
        if is_kde_wayland() && is_kwtype_available() {
            info!("Using kwtype for direct text input on KDE Wayland");
            type_text_via_kwtype(text)?;
            return Ok(true);
        }
        if !is_kde_wayland() && !is_gnome_wayland() && is_wtype_available() {
            info!("Using wtype for direct text input");
            type_text_via_wtype(text)?;
            return Ok(true);
        }
        if is_dotool_available() {
            info!("Using dotool for direct text input");
            type_text_via_dotool(text)?;
            return Ok(true);
        }
        if is_ydotool_available() {
            info!("Using ydotool for direct text input");
            type_text_via_ydotool(text)?;
            return Ok(true);
        }
    } else {
        if is_xdotool_available() {
            info!("Using xdotool for direct text input");
            type_text_via_xdotool(text)?;
            return Ok(true);
        }
        if is_ydotool_available() {
            info!("Using ydotool for direct text input");
            type_text_via_ydotool(text)?;
            return Ok(true);
        }
    }

    Ok(false)
}

/// Returns the list of available typing tools on this system.
/// Always includes "auto" as the first entry.
#[cfg(target_os = "linux")]
pub fn get_available_typing_tools() -> Vec<String> {
    let mut tools = vec!["auto".to_string()];
    if is_wtype_available() {
        tools.push("wtype".to_string());
    }
    if is_kwtype_available() {
        tools.push("kwtype".to_string());
    }
    if is_dotool_available() {
        tools.push("dotool".to_string());
    }
    if is_ydotool_available() {
        tools.push("ydotool".to_string());
    }
    if is_xdotool_available() {
        tools.push("xdotool".to_string());
    }
    tools
}

/// Check if wtype is available (Wayland text input tool)
#[cfg(target_os = "linux")]
fn is_wtype_available() -> bool {
    Command::new("which")
        .arg("wtype")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if dotool is available (another Wayland text input tool)
#[cfg(target_os = "linux")]
fn is_dotool_available() -> bool {
    Command::new("which")
        .arg("dotool")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YdotoolKeySyntax {
    Symbolic,
    RawKeycodes,
}

#[cfg(target_os = "linux")]
const YDOTOOL_UNKNOWN_HELP_FALLBACK: YdotoolKeySyntax = YdotoolKeySyntax::RawKeycodes;

#[cfg(target_os = "linux")]
static YDOTOOL_KEY_SYNTAX: OnceLock<YdotoolKeySyntax> = OnceLock::new();

#[cfg(target_os = "linux")]
fn classify_ydotool_key_syntax(help: &str) -> Option<YdotoolKeySyntax> {
    let help = help.to_ascii_lowercase();
    if help.contains("syntax: <keycode>:<pressed>")
        || help.contains("[keycodes]")
        || help.contains("using raw keycodes")
    {
        Some(YdotoolKeySyntax::RawKeycodes)
    } else if help.contains("separated by plus (+)")
        || (help.contains("<key sequence>") && help.contains("alt+r"))
    {
        Some(YdotoolKeySyntax::Symbolic)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn detect_ydotool_key_syntax() -> YdotoolKeySyntax {
    if let Some(syntax) = YDOTOOL_KEY_SYNTAX.get() {
        return *syntax;
    }
    match Command::new("ydotool").args(["key", "--help"]).output() {
        Ok(output) => {
            let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
            if !help.is_empty() && !output.stderr.is_empty() {
                help.push('\n');
            }
            help.push_str(&String::from_utf8_lossy(&output.stderr));
            if let Some(syntax) = classify_ydotool_key_syntax(&help) {
                *YDOTOOL_KEY_SYNTAX.get_or_init(|| syntax)
            } else {
                YDOTOOL_UNKNOWN_HELP_FALLBACK
            }
        }
        Err(_) => YDOTOOL_UNKNOWN_HELP_FALLBACK,
    }
}

/// Check if ydotool is available (uinput-based, works on both Wayland and X11)
#[cfg(target_os = "linux")]
fn is_ydotool_available() -> bool {
    Command::new("which")
        .arg("ydotool")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn is_xdotool_available() -> bool {
    Command::new("which")
        .arg("xdotool")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if kwtype is available (KDE Wayland virtual keyboard input tool)
#[cfg(target_os = "linux")]
fn is_kwtype_available() -> bool {
    Command::new("which")
        .arg("kwtype")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if wl-copy is available (Wayland clipboard tool)
#[cfg(target_os = "linux")]
fn is_wl_copy_available() -> bool {
    TrustedExecutable::resolve("wl-copy").is_some()
}

#[cfg(target_os = "linux")]
fn run_named_helper(name: &str, args: &[&str], input: &[u8]) -> Result<(), String> {
    let executable = TrustedExecutable::resolve(name)
        .ok_or_else(|| format!("{name} is not available from a trusted system path"))?;
    let status = run_trusted(
        &executable,
        args,
        input,
        crate::focused_output::CHILD_PROCESS_DEADLINE,
    )
    .map_err(|error| format!("Failed to execute {name}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} failed"))
    }
}

/// Type text directly via wtype on Wayland.
#[cfg(target_os = "linux")]
fn type_text_via_wtype(text: &str) -> Result<(), String> {
    let output = Command::new("wtype")
        .arg("--")
        .arg(text)
        .output()
        .map_err(|e| format!("Failed to execute wtype: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "wtype failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}
/// Type text directly via xdotool on X11.
#[cfg(target_os = "linux")]
fn type_text_via_xdotool(text: &str) -> Result<(), String> {
    let output = Command::new("xdotool")
        .args(["type", "--clearmodifiers", "--", text])
        .output()
        .map_err(|e| format!("Failed to execute xdotool: {}", e))?;
    let cleanup = Command::new("xdotool")
        .arg("keyup")
        .args([
            "Control_L",
            "Control_R",
            "Shift_L",
            "Shift_R",
            "Alt_L",
            "Alt_R",
            "Super_L",
            "Super_R",
        ])
        .output();
    if let Err(error) = cleanup {
        log::warn!("Failed to execute xdotool modifier cleanup: {}", error);
    }
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "xdotool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Type text directly via dotool.
#[cfg(target_os = "linux")]
fn type_text_via_dotool(text: &str) -> Result<(), String> {
    let mut child = Command::new("dotool")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn dotool: {}", e))?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "type {}", text)
            .map_err(|e| format!("Failed to write to dotool stdin: {}", e))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for dotool: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dotool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}
/// Type text directly via ydotool (uinput-based, requires ydotoold daemon).
#[cfg(target_os = "linux")]
fn type_text_via_ydotool(text: &str) -> Result<(), String> {
    let output = Command::new("ydotool")
        .arg("type")
        .arg("--")
        .arg(text)
        .output()
        .map_err(|e| format!("Failed to execute ydotool: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ydotool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}
/// Type text directly via kwtype.
#[cfg(target_os = "linux")]
fn type_text_via_kwtype(text: &str) -> Result<(), String> {
    let output = Command::new("kwtype")
        .arg("--")
        .arg(text)
        .output()
        .map_err(|e| format!("Failed to execute kwtype: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "kwtype failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Write text to clipboard via wl-copy (Wayland clipboard tool).
///
/// Transcript text is provided only over stdin, never argv, and child output is
/// discarded. The child is killed and reaped if it exceeds the focused-output
/// process deadline.
#[cfg(target_os = "linux")]
fn write_clipboard_via_wl_copy(text: &str) -> Result<(), String> {
    run_named_helper("wl-copy", &[], text.as_bytes())
}

/// Send a key combination (e.g., Ctrl+V) via wtype on Wayland.
#[cfg(target_os = "linux")]
fn send_key_combo_via_wtype(paste_method: &PasteMethod) -> Result<(), String> {
    let args: Vec<&str> = match paste_method {
        PasteMethod::CtrlV => vec!["-M", "ctrl", "-k", "v", "-m", "ctrl"],
        PasteMethod::ShiftInsert => vec!["-M", "shift", "-k", "Insert", "-m", "shift"],
        PasteMethod::CtrlShiftV => vec![
            "-M", "ctrl", "-M", "shift", "-k", "v", "-m", "shift", "-m", "ctrl",
        ],
        _ => return Err("Unsupported paste method".into()),
    };
    let output = Command::new("wtype")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute wtype: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "wtype failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Send a key combination (e.g., Ctrl+V) via dotool.
#[cfg(target_os = "linux")]
fn send_key_combo_via_dotool(paste_method: &PasteMethod) -> Result<(), String> {
    let command = match paste_method {
        PasteMethod::CtrlV => "echo key ctrl+v | dotool",
        PasteMethod::ShiftInsert => "echo key shift+insert | dotool",
        PasteMethod::CtrlShiftV => "echo key ctrl+shift+v | dotool",
        _ => return Err("Unsupported paste method".into()),
    };
    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Failed to execute dotool: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err("dotool failed".into())
    }
}

#[cfg(target_os = "linux")]
fn ydotool_key_args(
    paste_method: &PasteMethod,
    syntax: YdotoolKeySyntax,
) -> Result<&'static [&'static str], String> {
    match (paste_method, syntax) {
        (PasteMethod::CtrlV, YdotoolKeySyntax::Symbolic) => Ok(&["key", "ctrl+v"]),
        (PasteMethod::CtrlShiftV, YdotoolKeySyntax::Symbolic) => Ok(&["key", "ctrl+shift+v"]),
        (PasteMethod::ShiftInsert, YdotoolKeySyntax::Symbolic) => Ok(&["key", "shift+insert"]),
        (PasteMethod::CtrlV, YdotoolKeySyntax::RawKeycodes) => {
            Ok(&["key", "29:1", "47:1", "47:0", "29:0"])
        }
        (PasteMethod::CtrlShiftV, YdotoolKeySyntax::RawKeycodes) => {
            Ok(&["key", "29:1", "42:1", "47:1", "47:0", "42:0", "29:0"])
        }
        (PasteMethod::ShiftInsert, YdotoolKeySyntax::RawKeycodes) => {
            Ok(&["key", "42:1", "110:1", "110:0", "42:0"])
        }
        _ => Err("Unsupported paste method".into()),
    }
}

/// Send a key combination (e.g., Ctrl+V) via ydotool (requires ydotoold daemon).
#[cfg(target_os = "linux")]
fn send_key_combo_via_ydotool(paste_method: &PasteMethod) -> Result<(), String> {
    let args = ydotool_key_args(paste_method, detect_ydotool_key_syntax())?;
    let output = Command::new("ydotool")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute ydotool: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ydotool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Send a key combination (e.g., Ctrl+V) via xdotool on X11.
#[cfg(target_os = "linux")]
fn send_key_combo_via_xdotool(paste_method: &PasteMethod) -> Result<(), String> {
    let key_combo = match paste_method {
        PasteMethod::CtrlV => "ctrl+v",
        PasteMethod::CtrlShiftV => "ctrl+shift+v",
        PasteMethod::ShiftInsert => "shift+Insert",
        _ => return Err("Unsupported paste method".into()),
    };
    let output = Command::new("xdotool")
        .arg("key")
        .arg("--clearmodifiers")
        .arg(key_combo)
        .output()
        .map_err(|e| format!("Failed to execute xdotool: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "xdotool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Pastes text by invoking an explicitly configured external script.
///
/// This preserves the existing external-script contract: the transcript is the
/// first argument. Focused-field output rejects this paste method before arming,
/// so it is never used by a focused session.
fn paste_via_external_script(text: &str, script_path: &str) -> Result<(), String> {
    info!("Pasting via external script: {}", script_path);
    let status = Command::new(script_path)
        .arg(text)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Failed to execute external script '{}': {}", script_path, e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "External script '{}' failed with exit code {:?}",
            script_path,
            status.code()
        ))
    }
}

/// Types text directly by simulating individual key presses.
fn paste_direct(
    text: &str,
    app_handle: &AppHandle,
    #[cfg(target_os = "linux")] typing_tool: TypingTool,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if try_direct_typing_linux(text, typing_tool)? {
            return Ok(());
        }
        info!("Falling back to enigo for direct text input");
    }

    with_enigo(app_handle, |enigo| input::paste_text_direct(enigo, text))
}

pub(crate) fn send_return_key(enigo: &mut Enigo, key_type: AutoSubmitKey) -> Result<(), String> {
    match key_type {
        AutoSubmitKey::Enter => {
            enigo
                .key(Key::Return, Direction::Press)
                .map_err(|e| format!("Failed to press Return key: {}", e))?;
            enigo
                .key(Key::Return, Direction::Release)
                .map_err(|e| format!("Failed to release Return key: {}", e))?;
        }
        AutoSubmitKey::CtrlEnter => {
            enigo
                .key(Key::Control, Direction::Press)
                .map_err(|e| format!("Failed to press Control key: {}", e))?;
            enigo
                .key(Key::Return, Direction::Press)
                .map_err(|e| format!("Failed to press Return key: {}", e))?;
            enigo
                .key(Key::Return, Direction::Release)
                .map_err(|e| format!("Failed to release Return key: {}", e))?;
            enigo
                .key(Key::Control, Direction::Release)
                .map_err(|e| format!("Failed to release Control key: {}", e))?;
        }
        AutoSubmitKey::CmdEnter => {
            enigo
                .key(Key::Meta, Direction::Press)
                .map_err(|e| format!("Failed to press Meta/Cmd key: {}", e))?;
            enigo
                .key(Key::Return, Direction::Press)
                .map_err(|e| format!("Failed to press Return key: {}", e))?;
            enigo
                .key(Key::Return, Direction::Release)
                .map_err(|e| format!("Failed to release Return key: {}", e))?;
            enigo
                .key(Key::Meta, Direction::Release)
                .map_err(|e| format!("Failed to release Meta/Cmd key: {}", e))?;
        }
    }

    Ok(())
}

fn should_send_auto_submit(auto_submit: bool, paste_method: PasteMethod) -> bool {
    auto_submit && paste_method != PasteMethod::None
}

pub fn paste(text: String, app_handle: AppHandle) -> Result<(), String> {
    let settings = get_settings(&app_handle);
    let paste_method = settings.paste_method;
    let paste_delay_ms = settings.paste_delay_ms;
    let paste_delay_after_ms = settings.paste_delay_after_ms;

    // Append trailing space if setting is enabled
    let text = if settings.append_trailing_space {
        format!("{} ", text)
    } else {
        text
    };

    info!(
        "Using paste method: {:?}, delay before: {}ms, delay after: {}ms",
        paste_method, paste_delay_ms, paste_delay_after_ms
    );

    // Perform the paste operation
    match paste_method {
        PasteMethod::None => {
            info!("PasteMethod::None selected - skipping paste action");
        }
        PasteMethod::Direct => {
            paste_direct(
                &text,
                &app_handle,
                #[cfg(target_os = "linux")]
                settings.typing_tool,
            )?;
        }
        PasteMethod::CtrlV | PasteMethod::CtrlShiftV | PasteMethod::ShiftInsert => {
            // Debug-gated receipt-sequenced paste (#502): restore the clipboard
            // after the target actually reads the transcript, not on a timer.
            // On success it fully handles the paste (including auto-submit and
            // clipboard handling) asynchronously; on failure fall through to
            // the legacy path untouched.
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            if settings.reliable_paste {
                let reliable_result = with_enigo(&app_handle, |enigo| {
                    crate::paste_tx::try_reliable_paste(
                        &text,
                        &app_handle,
                        &paste_method,
                        enigo,
                        settings.auto_submit,
                        settings.auto_submit_key,
                        settings.clipboard_handling,
                    )
                });
                match reliable_result {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        log::warn!("Reliable paste unavailable ({e}); falling back to legacy paste")
                    }
                }
            }
            paste_via_clipboard(
                &text,
                &app_handle,
                &paste_method,
                paste_delay_ms,
                paste_delay_after_ms,
            )?
        }
        PasteMethod::ExternalScript => {
            let script_path = settings
                .external_script_path
                .as_ref()
                .filter(|p| !p.is_empty())
                .ok_or("External script path is not configured")?;
            paste_via_external_script(&text, script_path)?;
        }
    }

    if should_send_auto_submit(settings.auto_submit, paste_method) {
        std::thread::sleep(Duration::from_millis(50));
        if let Err(error) = with_enigo(&app_handle, |enigo| {
            send_return_key(enigo, settings.auto_submit_key)
        }) {
            log::warn!("Paste succeeded, but auto-submit failed: {error}");
        }
    }

    // After pasting, optionally copy to clipboard based on settings
    if settings.clipboard_handling == ClipboardHandling::CopyToClipboard {
        write_text_to_clipboard(&app_handle, &text)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[cfg(target_os = "linux")]
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn generates_ydotool_arguments_for_both_supported_syntaxes() {
        assert_eq!(
            ydotool_key_args(&PasteMethod::CtrlV, YdotoolKeySyntax::RawKeycodes).unwrap(),
            ["key", "29:1", "47:1", "47:0", "29:0"]
        );
        assert_eq!(
            ydotool_key_args(&PasteMethod::CtrlShiftV, YdotoolKeySyntax::RawKeycodes).unwrap(),
            ["key", "29:1", "42:1", "47:1", "47:0", "42:0", "29:0"]
        );
        assert_eq!(
            ydotool_key_args(&PasteMethod::ShiftInsert, YdotoolKeySyntax::Symbolic).unwrap(),
            ["key", "shift+insert"]
        );
        assert_eq!(
            classify_ydotool_key_syntax("Syntax: <keycode>:<pressed>"),
            Some(YdotoolKeySyntax::RawKeycodes)
        );
        assert_eq!(
            classify_ydotool_key_syntax("keys separated by plus (+), e.g. alt+r"),
            Some(YdotoolKeySyntax::Symbolic)
        );
    }

    #[test]
    fn auto_submit_requires_setting_enabled() {
        assert!(!should_send_auto_submit(false, PasteMethod::CtrlV));
        assert!(!should_send_auto_submit(false, PasteMethod::Direct));
    }

    #[test]
    fn auto_submit_skips_none_paste_method() {
        assert!(!should_send_auto_submit(true, PasteMethod::None));
    }

    #[test]
    fn auto_submit_runs_for_active_paste_methods() {
        assert!(should_send_auto_submit(true, PasteMethod::CtrlV));
        assert!(should_send_auto_submit(true, PasteMethod::Direct));
        assert!(should_send_auto_submit(true, PasteMethod::CtrlShiftV));
        assert!(should_send_auto_submit(true, PasteMethod::ShiftInsert));
    }

    #[test]
    fn clipboard_is_restored_before_key_injection_error_is_returned() {
        let restored = Cell::new(false);
        let result = finish_clipboard_paste(Err("input failed".into()), 0, || {
            restored.set(true);
        });

        assert_eq!(result.unwrap_err(), "input failed");
        assert!(restored.get());
    }

    #[cfg(unix)]
    #[test]
    fn external_script_does_not_wait_for_inherited_stdio() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;
        use std::thread;

        let script_path = std::env::temp_dir().join(format!(
            "handy-external-script-{}-{}.sh",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after UNIX_EPOCH")
                .as_nanos()
        ));
        fs::write(&script_path, "#!/bin/sh\nsleep 3 &\nexit 0\n").expect("write external script");
        let mut permissions = fs::metadata(&script_path)
            .expect("read external script metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script_path, permissions).expect("make external script executable");

        let (sender, receiver) = mpsc::channel();
        let script_path_for_thread = script_path.clone();
        thread::spawn(move || {
            let result =
                paste_via_external_script("test", script_path_for_thread.to_str().unwrap());
            sender.send(result).expect("send script result");
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("external script should return without waiting for its child");
        fs::remove_file(script_path).expect("remove external script");
        assert!(result.is_ok());
    }
    #[cfg(target_os = "linux")]
    fn test_executable(source: &Path, name: &str, mode: u32) -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "handy-trusted-exec-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(name);
        fs::copy(source, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        (directory, path)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn untrusted_path_precedence_is_skipped() {
        let (directory, attacker) = test_executable(Path::new("/usr/bin/bash"), "cat", 0o755);
        let marker = directory.join("attacker-ran");
        fs::write(
            &attacker,
            format!("#!/usr/bin/bash\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&attacker, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = TrustedExecutable::resolve_in_paths(
            "cat",
            [directory.clone(), PathBuf::from("/usr/bin")],
        )
        .expect("trusted system cat");
        assert!(run_trusted(
            &executable,
            &[],
            b"private transcript",
            Duration::from_secs(1)
        )
        .unwrap()
        .success());
        assert!(!marker.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_and_writable_executables_are_rejected() {
        use std::os::unix::fs::symlink;
        let (directory, writable) = test_executable(Path::new("/usr/bin/cat"), "writable", 0o777);
        assert!(TrustedExecutable::open_for_test(&writable).is_err());
        let link = directory.join("link");
        symlink("/usr/bin/cat", &link).unwrap();
        assert!(TrustedExecutable::open(&link).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacement_never_receives_pinned_transcript() {
        let (directory, path) = test_executable(Path::new("/usr/bin/cat"), "tool", 0o555);
        let executable = TrustedExecutable::open_for_test(&path).unwrap();
        let old = directory.join("old");
        fs::rename(&path, &old).unwrap();
        let marker = directory.join("replacement-ran");
        fs::write(
            &path,
            format!("#!/usr/bin/bash\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        let _ = run_trusted(
            &executable,
            &[],
            b"private transcript",
            Duration::from_secs(1),
        );
        assert!(!marker.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_pinned_object_executes_from_its_fd() {
        let (directory, path) = test_executable(Path::new("/usr/bin/cat"), "tool", 0o555);
        let executable = TrustedExecutable::open_for_test(&path).unwrap();
        assert!(run_trusted(
            &executable,
            &[],
            b"private transcript",
            Duration::from_secs(1)
        )
        .unwrap()
        .success());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_nonreader_is_killed_before_deadline() {
        let (directory, path) = test_executable(Path::new("/usr/bin/bash"), "tool", 0o555);
        let executable = TrustedExecutable::open_for_test(&path).unwrap();
        let started = Instant::now();
        let input = vec![b'x'; 4 * 1024 * 1024];
        assert!(run_trusted(
            &executable,
            &["-c", "(trap '' PIPE; sleep 30) & exit 0"],
            &input,
            Duration::from_millis(100)
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn focused_clipboard_copy_invokes_only_the_writer_once() {
        let calls = Cell::new(0);
        let copied = copy_text_with("final speech ", |text| {
            calls.set(calls.get() + 1);
            Ok(text.to_owned())
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(copied, "final speech ");
    }
}
