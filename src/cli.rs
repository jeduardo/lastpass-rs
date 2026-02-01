#![forbid(unsafe_code)]

use std::path::Path;

use crate::commands;
use crate::version;

#[derive(Copy, Clone)]
struct CommandSpec {
    name: &'static str,
    usage: &'static str,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "version",
        usage: "version",
    },
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

fn dispatch(args: &[String]) -> Dispatch {
    if args.len() <= 1 {
        return Dispatch::HelpOnly;
    }

    let arg = args[1].as_str();
    if arg == "version" {
        return if args.len() == 2 {
            Dispatch::VersionOnly
        } else {
            Dispatch::HelpOnly
        };
    }

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

fn program_names(args: &[String]) -> (String, String) {
    let program_path = args
        .get(0)
        .cloned()
        .unwrap_or_else(|| "lpass".to_string());
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
