#![forbid(unsafe_code)]

mod add;
mod data;
mod duplicate;
mod edit;
mod export;
mod generate;
mod login;
mod logout;
mod ls;
mod show;
mod status;

pub fn run(command: &str, args: &[String]) -> i32 {
    match command {
        "add" => add::run(args),
        "edit" => edit::run(args),
        "duplicate" => duplicate::run(args),
        "export" => export::run(args),
        "generate" => generate::run(args),
        "login" => login::run(args),
        "logout" => logout::run(args),
        "show" => show::run(args),
        "ls" => ls::run(args),
        "status" => status::run(args),
        "passwd" | "mv" | "rm" | "sync" | "import" | "share" => not_implemented(command),
        _ => 1,
    }
}

fn not_implemented(command: &str) -> i32 {
    eprintln!("error: command '{}' not implemented", command);
    1
}
