#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut command = build_bash_command(&root, &args);

    let status = command.status();
    if let Err(err) = &status {
        eprintln!("error: failed to run upstream shell tests: {err}");
    }
    map_status(status)
}

fn script_path(root: &std::path::Path) -> PathBuf {
    root.join("scripts/run-upstream-shell-tests.sh")
}

fn build_bash_command(root: &std::path::Path, args: &[String]) -> Command {
    let script = script_path(root);
    let mut command = Command::new("bash");
    command.arg(script);
    command.args(args);
    command.current_dir(root);
    command
}

fn map_status(status: std::io::Result<std::process::ExitStatus>) -> ExitCode {
    match status {
        Ok(code) if code.success() => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code.code().unwrap_or(1) as u8),
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_bash_command, map_status, script_path};
    use std::io;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn script_path_points_to_runner_script() {
        let path = script_path(Path::new("/tmp/repo"));
        assert_eq!(
            path,
            Path::new("/tmp/repo/scripts/run-upstream-shell-tests.sh")
        );
    }

    #[test]
    fn map_status_maps_success_failure_and_error() {
        let success = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .status()
            .expect("status");
        assert_eq!(map_status(Ok(success)), std::process::ExitCode::SUCCESS);

        let failure = Command::new("sh")
            .arg("-c")
            .arg("exit 7")
            .status()
            .expect("status");
        assert_eq!(map_status(Ok(failure)), std::process::ExitCode::from(7));

        let err = io::Error::new(io::ErrorKind::NotFound, "missing");
        assert_eq!(map_status(Err(err)), std::process::ExitCode::from(1));
    }

    #[test]
    fn build_bash_command_sets_program_script_args_and_cwd() {
        let root = Path::new("/tmp/repo");
        let args = vec!["test_login".to_string(), "test_ls".to_string()];
        let command = build_bash_command(root, &args);

        assert_eq!(command.get_program(), "bash");
        let collected: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            collected,
            vec![
                "/tmp/repo/scripts/run-upstream-shell-tests.sh".to_string(),
                "test_login".to_string(),
                "test_ls".to_string()
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/tmp/repo")));
    }
}
