#![forbid(unsafe_code)]

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
