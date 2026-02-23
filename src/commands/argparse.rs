#![forbid(unsafe_code)]

use std::iter::Peekable;
use std::slice::Iter;

use crate::commands::data::SyncMode;

pub(crate) fn parse_sync_option(
    arg: &str,
    iter: &mut Peekable<Iter<'_, String>>,
    usage: &str,
) -> Result<Option<SyncMode>, String> {
    if let Some(value) = arg.strip_prefix("--sync=") {
        let mode = SyncMode::parse(value).ok_or_else(|| usage.to_string())?;
        return Ok(Some(mode));
    }

    if arg == "--sync" {
        let value = iter.next().ok_or_else(|| usage.to_string())?;
        let mode = SyncMode::parse(value).ok_or_else(|| usage.to_string())?;
        return Ok(Some(mode));
    }

    Ok(None)
}

#[allow(dead_code)]
pub(crate) fn parse_bool_arg_string(extra: Option<&str>) -> bool {
    match extra {
        None => true,
        Some(value) => value == "true",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sync_option_supports_equals_and_separate_values() {
        let usage = "usage";

        let arg = "--sync=NOW".to_string();
        let args = [arg];
        let mut iter = args.iter().peekable();
        let parsed = parse_sync_option(args[0].as_str(), &mut iter, usage).expect("parse");
        assert_eq!(parsed, Some(SyncMode::Now));

        let args = ["--sync".to_string(), "no".to_string()];
        let mut iter = args.iter().peekable();
        let first = iter.next().expect("first");
        let parsed = parse_sync_option(first, &mut iter, usage).expect("parse");
        assert_eq!(parsed, Some(SyncMode::No));
    }

    #[test]
    fn parse_sync_option_rejects_invalid_or_missing_values() {
        let usage = "usage";

        let arg = "--sync=invalid".to_string();
        let args = [arg];
        let mut iter = args.iter().peekable();
        let err = parse_sync_option(args[0].as_str(), &mut iter, usage).expect_err("must fail");
        assert_eq!(err, "usage");

        let args = ["--sync".to_string()];
        let mut iter = args.iter().peekable();
        let first = iter.next().expect("first");
        let err = parse_sync_option(first, &mut iter, usage).expect_err("must fail");
        assert_eq!(err, "usage");
    }

    #[test]
    fn parse_bool_arg_string_matches_c_behavior() {
        assert!(parse_bool_arg_string(None));
        assert!(parse_bool_arg_string(Some("true")));
        assert!(!parse_bool_arg_string(Some("false")));
        assert!(!parse_bool_arg_string(Some("anything")));
    }
}
