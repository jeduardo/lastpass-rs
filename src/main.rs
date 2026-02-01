#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = lpass_core::agent::maybe_run_agent(&args) {
        std::process::exit(code);
    }
    let exit_code = lpass_core::cli::run(args);
    std::process::exit(exit_code);
}
