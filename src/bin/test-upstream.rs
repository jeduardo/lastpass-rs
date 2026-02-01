#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = root.join("scripts/run-upstream-shell-tests.sh");

    let mut command = Command::new("bash");
    command.arg(script);
    command.args(std::env::args().skip(1));
    command.current_dir(&root);

    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(err) => {
            eprintln!("error: failed to run upstream shell tests: {err}");
            ExitCode::from(1)
        }
    }
}
