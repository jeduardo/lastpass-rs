use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/modules/lastpass-cli/HEAD");
    println!("cargo:rerun-if-changed=lastpass-cli");

    let repo_sha =
        git_value(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let upstream_version = git_value(&[
        "-C",
        "lastpass-cli",
        "describe",
        "--match",
        "v[0-9]*",
        "--always",
        "--dirty",
    ])
    .unwrap_or_else(|| "unknown".to_string());
    let upstream_sha = git_value(&["-C", "lastpass-cli", "rev-parse", "--short=12", "HEAD"])
        .unwrap_or_else(|| "unknown".to_string());
    let rustc_version = rustc_version().unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=LPASS_RS_GIT_SHA={repo_sha}");
    println!("cargo:rustc-env=LPASS_UPSTREAM_VERSION={upstream_version}");
    println!("cargo:rustc-env=LPASS_UPSTREAM_SHA={upstream_sha}");
    println!("cargo:rustc-env=LPASS_RUSTC_VERSION={rustc_version}");
}

fn git_value(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn rustc_version() -> Option<String> {
    let output = Command::new("rustc").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
