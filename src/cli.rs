#![forbid(unsafe_code)]

use std::path::Path;

use crate::commands;
use crate::config::config_read_string;
use crate::lpenv;
use crate::terminal;
use crate::version;

#[derive(Copy, Clone)]
struct CommandSpec {
    name: &'static str,
    usage: &'static str,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "login",
        usage: "login [--trust] [--plaintext-key [--force, -f]] [--color=auto|never|always] USERNAME",
    },
    CommandSpec {
        name: "logout",
        usage: "logout [--force, -f] [--color=auto|never|always]",
    },
    CommandSpec {
        name: "passwd",
        usage: "passwd",
    },
    CommandSpec {
        name: "show",
        usage: "show [--sync=auto|now|no] [--clip, -c] [--quiet, -q] [--expand-multi, -x] [--json, -j] [--all|--username|--password|--url|--notes|--field=FIELD|--id|--name|--attach=ATTACHID] [--basic-regexp, -G|--fixed-strings, -F] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}",
    },
    CommandSpec {
        name: "ls",
        usage: "ls [--sync=auto|now|no] [--long, -l] [-m] [-u] [--color=auto|never|always] [GROUP]",
    },
    CommandSpec {
        name: "mv",
        usage: "mv [--color=auto|never|always] {UNIQUENAME|UNIQUEID} GROUP",
    },
    CommandSpec {
        name: "add",
        usage: "add [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--username|--password|--url|--notes|--field=FIELD|--note-type=NOTETYPE} NAME",
    },
    CommandSpec {
        name: "edit",
        usage: "edit [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}",
    },
    CommandSpec {
        name: "generate",
        usage: "generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH",
    },
    CommandSpec {
        name: "duplicate",
        usage: "duplicate [--sync=auto|now|no] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}",
    },
    CommandSpec {
        name: "rm",
        usage: "rm [--sync=auto|now|no] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}",
    },
    CommandSpec {
        name: "status",
        usage: "status [--quiet, -q] [--color=auto|never|always]",
    },
    CommandSpec {
        name: "sync",
        usage: "sync [--background, -b] [--color=auto|never|always]",
    },
    CommandSpec {
        name: "export",
        usage: "export [--sync=auto|now|no] [--color=auto|never|always] [--fields=FIELDLIST]",
    },
    CommandSpec {
        name: "import",
        usage: "import [--keep-dupes] [CSV_FILENAME]",
    },
    CommandSpec {
        name: "share",
        usage: "share subcommand sharename ...",
    },
];

enum Dispatch {
    HelpOnly,
    HelpWithVersion,
    VersionOnly,
    Command { name: String, args: Vec<String> },
}

pub fn run(args: Vec<String>) -> i32 {
    let args = expand_aliases(args);
    apply_requested_color_mode(&args);
    if let Err(err) = lpenv::reload_saved_environment() {
        eprintln!(
            "{}",
            terminal::cli_warning_text(&format!("failed to load saved environment: {err}"))
        );
    }

    let (program_path, program_name) = program_names(&args);
    match dispatch(&args) {
        Dispatch::HelpOnly => {
            print_help(&program_path, &program_name);
            1
        }
        Dispatch::HelpWithVersion => {
            println!("{}", version::version_string());
            println!();
            print_help(&program_path, &program_name);
            0
        }
        Dispatch::VersionOnly => {
            println!("{}", version::version_string());
            0
        }
        Dispatch::Command { name, args } => {
            if is_known_command(&name) {
                commands::run(&name, &args)
            } else {
                print_help(&program_path, &program_name);
                1
            }
        }
    }
}

fn expand_aliases(args: Vec<String>) -> Vec<String> {
    if args.len() < 2 {
        return args;
    }
    if args[1].starts_with('-') {
        return args;
    }

    let alias_name = args[1].clone();
    let alias_key = format!("alias.{alias_name}");
    let alias_value = match config_read_string(&alias_key) {
        Ok(Some(value)) => value,
        Ok(None) => return args,
        Err(_) => return args,
    };

    let mut expanded: Vec<String> = Vec::new();
    expanded.push(args[0].clone());
    for token in alias_value.split_whitespace() {
        expanded.push(token.to_string());
    }
    expanded.extend(args.into_iter().skip(2));
    expanded
}

fn dispatch(args: &[String]) -> Dispatch {
    if args.len() <= 1 {
        return Dispatch::HelpOnly;
    }

    let arg = args[1].as_str();
    if arg.starts_with('-') {
        return match arg {
            "-h" | "--help" => Dispatch::HelpWithVersion,
            "-v" | "--version" => Dispatch::VersionOnly,
            _ => Dispatch::HelpOnly,
        };
    }

    Dispatch::Command {
        name: arg.to_string(),
        args: args[2..].to_vec(),
    }
}

fn apply_requested_color_mode(args: &[String]) {
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--color" {
            let Some(value) = iter.next() else {
                continue;
            };
            if let Some(mode) = terminal::parse_color_mode(value) {
                terminal::set_color_mode(mode);
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            if let Some(mode) = terminal::parse_color_mode(value) {
                terminal::set_color_mode(mode);
            }
        }
    }
}

fn program_names(args: &[String]) -> (String, String) {
    let program_path = args.first().cloned().unwrap_or_else(|| "lpass".to_string());
    let program_name = Path::new(&program_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lpass")
        .to_string();
    (program_path, program_name)
}

fn is_known_command(name: &str) -> bool {
    COMMANDS.iter().any(|cmd| cmd.name == name)
}

fn print_help(program_path: &str, program_name: &str) {
    println!("Usage:");
    println!("  {} {{--help|--version}}", program_path);
    for cmd in COMMANDS {
        println!("  {} {}", program_name, cmd.usage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigEnv, config_path, config_write_string, set_test_env};
    use tempfile::TempDir;

    #[test]
    fn expand_aliases_keeps_args_when_no_alias_exists() {
        let args = vec![
            "lpass".to_string(),
            "show".to_string(),
            "team/item".to_string(),
        ];
        assert_eq!(expand_aliases(args.clone()), args);
    }

    #[test]
    fn expand_aliases_expands_alias_command_and_preserves_tail() {
        let temp = TempDir::new().expect("tempdir");
        let _guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        config_write_string("alias.passclip", "show --password -c").expect("alias write");

        let args = vec![
            "lpass".to_string(),
            "passclip".to_string(),
            "test-group/test-account".to_string(),
        ];
        let expanded = expand_aliases(args);
        assert_eq!(
            expanded,
            vec![
                "lpass".to_string(),
                "show".to_string(),
                "--password".to_string(),
                "-c".to_string(),
                "test-group/test-account".to_string(),
            ]
        );
    }

    #[test]
    fn expand_aliases_does_not_apply_to_global_flags() {
        let args = vec!["lpass".to_string(), "--help".to_string()];
        assert_eq!(expand_aliases(args.clone()), args);
    }

    #[test]
    fn expand_aliases_ignores_alias_read_errors() {
        let temp = TempDir::new().expect("tempdir");
        let _guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let alias_path = config_path("alias.badalias").expect("alias path");
        std::fs::create_dir_all(&alias_path).expect("make alias dir");

        let args = vec![
            "lpass".to_string(),
            "badalias".to_string(),
            "test-group/test-account".to_string(),
        ];
        assert_eq!(expand_aliases(args.clone()), args);
    }

    #[test]
    fn dispatch_treats_unknown_global_flags_as_help_only() {
        let args = vec!["lpass".to_string(), "--bogus".to_string()];
        assert!(matches!(dispatch(&args), Dispatch::HelpOnly));
    }

    #[test]
    fn apply_requested_color_mode_uses_command_flag_values() {
        terminal::set_color_mode(terminal::ColorMode::Auto);
        apply_requested_color_mode(&[
            "lpass".to_string(),
            "status".to_string(),
            "--color=never".to_string(),
        ]);
        assert_eq!(
            terminal::render_stderr(&format!(
                "{}{}Warning{}: café",
                terminal::FG_YELLOW,
                terminal::BOLD,
                terminal::RESET
            )),
            "Warning: café"
        );

        apply_requested_color_mode(&[
            "lpass".to_string(),
            "status".to_string(),
            "--color=always".to_string(),
        ]);
        let rendered = terminal::render_stderr(&format!(
            "{}{}Warning{}: café",
            terminal::FG_YELLOW,
            terminal::BOLD,
            terminal::RESET
        ));
        assert!(rendered.contains("\x1b["), "rendered: {rendered}");
    }

    #[test]
    fn apply_requested_color_mode_ignores_invalid_or_missing_values() {
        terminal::set_color_mode(terminal::ColorMode::Auto);
        apply_requested_color_mode(&[
            "lpass".to_string(),
            "status".to_string(),
            "--color".to_string(),
        ]);
        let rendered = terminal::render_stderr(&format!(
            "{}{}Warning{}: café",
            terminal::FG_YELLOW,
            terminal::BOLD,
            terminal::RESET
        ));
        assert_eq!(rendered, "Warning: café");

        apply_requested_color_mode(&[
            "lpass".to_string(),
            "status".to_string(),
            "--color=rainbow".to_string(),
        ]);
        let rendered = terminal::render_stderr(&format!(
            "{}{}Warning{}: café",
            terminal::FG_YELLOW,
            terminal::BOLD,
            terminal::RESET
        ));
        assert_eq!(rendered, "Warning: café");
    }
}
