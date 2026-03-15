#![forbid(unsafe_code)]

#[test]
fn share_dispatch_help_path_is_exercised_in_binary_tests() {
    let code = lpass_core::commands::run("share", &[]);
    assert_eq!(code, 1);
}

#[test]
fn share_dispatch_usage_path_is_exercised_in_binary_tests() {
    let code = lpass_core::commands::run("share", &[String::from("userls")]);
    assert_eq!(code, 1);
}
