#![forbid(unsafe_code)]

use std::env;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ColorMode {
    Auto = 0,
    Never = 1,
    Always = 2,
}

static COLOR_MODE: AtomicU8 = AtomicU8::new(ColorMode::Auto as u8);

pub const FG_RED: &str = "\x1b[31m";
pub const FG_GREEN: &str = "\x1b[32m";
pub const FG_BLUE: &str = "\x1b[34m";
pub const FG_CYAN: &str = "\x1b[36m";
pub const FG_YELLOW: &str = "\x1b[33m";
pub const BOLD: &str = "\x1b[1m";
pub const NO_BOLD: &str = "\x1b[22m";
pub const UNDERLINE: &str = "\x1b[4m";
pub const RESET: &str = "\x1b[0m";

pub fn set_color_mode(mode: ColorMode) {
    COLOR_MODE.store(mode as u8, Ordering::Relaxed);
}

pub fn parse_color_mode(value: &str) -> Option<ColorMode> {
    match value {
        "auto" => Some(ColorMode::Auto),
        "never" => Some(ColorMode::Never),
        "always" => Some(ColorMode::Always),
        _ => None,
    }
}

pub fn render_stdout(text: &str) -> String {
    render(text, std::io::stdout().is_terminal())
}

pub fn render_stderr(text: &str) -> String {
    render(text, std::io::stderr().is_terminal())
}

pub fn cli_usage_text(usage: &str) -> String {
    format_cli_usage(&current_program_path(), usage, std::io::stderr().is_terminal())
}

pub fn cli_error_text(message: &str) -> String {
    render_stderr(&format!("{FG_RED}{BOLD}Error{RESET}: {message}"))
}

pub fn cli_warning_text(message: &str) -> String {
    render_stderr(&format!("{FG_YELLOW}{BOLD}Warning{RESET}: {message}"))
}

pub fn cli_failure_text(message: &str) -> String {
    if is_usage_text(message) {
        cli_usage_text(message)
    } else {
        cli_error_text(message)
    }
}

fn render(text: &str, is_tty: bool) -> String {
    let mode = match COLOR_MODE.load(Ordering::Relaxed) {
        1 => ColorMode::Never,
        2 => ColorMode::Always,
        _ => ColorMode::Auto,
    };

    let use_color = match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_tty,
    };

    if use_color {
        text.to_string()
    } else {
        strip_ansi(text)
    }
}

fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() {
                let ch = bytes[i];
                i += 1;
                if (ch as char).is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn current_program_path() -> String {
    env::args().next().unwrap_or_else(|| "lpass".to_string())
}

fn is_usage_text(message: &str) -> bool {
    message.starts_with("usage: ")
}

fn format_cli_usage(program_path: &str, usage: &str, is_tty: bool) -> String {
    let usage = usage.strip_prefix("usage: ").unwrap_or(usage);
    render_with_mode(&format!("Usage: {program_path} {usage}"), is_tty, current_mode())
}

fn current_mode() -> ColorMode {
    match COLOR_MODE.load(Ordering::Relaxed) {
        1 => ColorMode::Never,
        2 => ColorMode::Always,
        _ => ColorMode::Auto,
    }
}

fn render_with_mode(text: &str, is_tty: bool, mode: ColorMode) -> String {
    let use_color = match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_tty,
    };

    if use_color {
        text.to_string()
    } else {
        strip_ansi(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cli_usage_prefixes_program_and_capitalizes_usage() {
        let text = format_cli_usage(
            "/tmp/lpass",
            "usage: status [--quiet, -q] [--color=auto|never|always]",
            false,
        );
        assert_eq!(
            text,
            "Usage: /tmp/lpass status [--quiet, -q] [--color=auto|never|always]"
        );
    }

    #[test]
    fn cli_failure_text_formats_errors_and_usages_differently() {
        set_color_mode(ColorMode::Never);
        assert_eq!(
            cli_failure_text("usage: status [--quiet, -q] [--color=auto|never|always]"),
            format_cli_usage(
                &current_program_path(),
                "usage: status [--quiet, -q] [--color=auto|never|always]",
                false
            )
        );
        assert_eq!(cli_failure_text("boom"), "Error: boom");
    }

    #[test]
    fn cli_warning_text_formats_warning_prefix() {
        set_color_mode(ColorMode::Never);
        assert_eq!(cli_warning_text("heads up"), "Warning: heads up");
    }

    #[test]
    fn render_with_mode_strips_or_keeps_ansi() {
        let text = format!("{FG_RED}{BOLD}Error{RESET}: boom");
        assert_eq!(render_with_mode(&text, false, ColorMode::Auto), "Error: boom");
        assert_eq!(render_with_mode(&text, false, ColorMode::Always), text);
    }
}
