#![forbid(unsafe_code)]

mod add;
mod argparse;
mod data;
mod duplicate;
mod edit;
mod export;
mod generate;
mod import;
mod login;
mod logout;
mod ls;
mod mv;
mod rm;
mod show;
mod status;
mod sync;

pub fn run(command: &str, args: &[String]) -> i32 {
    match command {
        "add" => add::run(args),
        "edit" => edit::run(args),
        "duplicate" => duplicate::run(args),
        "export" => export::run(args),
        "generate" => generate::run(args),
        "import" => import::run(args),
        "login" => login::run(args),
        "logout" => logout::run(args),
        "show" => show::run(args),
        "ls" => ls::run(args),
        "mv" => mv::run(args),
        "rm" => rm::run(args),
        "status" => status::run(args),
        "sync" => sync::run(args),
        "passwd" | "share" => not_implemented(command),
        _ => 1,
    }
}

fn not_implemented(command: &str) -> i32 {
    eprintln!("error: command '{}' not implemented", command);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_reports_unimplemented_and_unknown_commands() {
        assert_eq!(run("passwd", &[]), 1);
        assert_eq!(run("share", &[]), 1);
        assert_eq!(run("unknown", &[]), 1);
    }
}
