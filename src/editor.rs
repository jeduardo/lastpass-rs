#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use tempfile::{Builder, NamedTempFile, TempDir};

pub fn edit_with_editor(initial: &str) -> Result<String, String> {
    let mut scratch = EditorScratch::new().map_err(|err| format!("mkstemp: {err}"))?;
    scratch
        .file
        .write_all(initial.as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    scratch
        .file
        .flush()
        .map_err(|err| format!("flush: {err}"))?;

    let editor = resolve_editor();
    let path = scratch.file.path().to_string_lossy().to_string();
    let _status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} {}", shell_quote(&path)))
        .status()
        .map_err(|err| format!("system($VISUAL): {err}"))?;

    fs::read_to_string(&path).map_err(|err| format!("read: {err}"))
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn resolve_editor() -> String {
    resolve_editor_from(
        crate::lpenv::var("VISUAL").ok(),
        crate::lpenv::var("EDITOR").ok(),
    )
}

fn resolve_editor_from(visual: Option<String>, editor: Option<String>) -> String {
    visual
        .filter(|value| !value.trim().is_empty())
        .or_else(|| editor.filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "vi".to_string())
}

struct EditorScratch {
    _dir: TempDir,
    file: NamedTempFile,
}

impl EditorScratch {
    fn new() -> std::io::Result<Self> {
        let dir = secure_temp_dir()?;
        let file = Builder::new().prefix("lpass.").tempfile_in(dir.path())?;
        Ok(Self { _dir: dir, file })
    }
}

fn secure_temp_dir() -> std::io::Result<TempDir> {
    Builder::new()
        .prefix("lpass.")
        .tempdir_in(secure_temp_base_dir())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn secure_temp_base_dir() -> PathBuf {
    PathBuf::from("/dev/shm")
}

#[cfg(target_os = "macos")]
fn secure_temp_base_dir() -> PathBuf {
    crate::lpenv::var_os("SECURE_TMPDIR")
        .map(PathBuf::from)
        .or_else(|| crate::lpenv::var_os("TMPDIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn secure_temp_base_dir() -> PathBuf {
    if let Some(path) = crate::lpenv::var_os("SECURE_TMPDIR") {
        return PathBuf::from(path);
    }

    let path = crate::lpenv::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    eprintln!(
        "Warning: Using {} as secure temporary directory.\nRecommend using tmpfs and encrypted swap.\nSet SECURE_TMPDIR environment variable to override.",
        path.display()
    );
    std::thread::sleep(std::time::Duration::from_secs(5));
    path
}

#[cfg(test)]
#[path = "editor_tests.rs"]
mod tests;
