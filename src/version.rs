#![forbid(unsafe_code)]

pub fn generated_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn version_string() -> String {
    let version = generated_version();
    let sha = env!("LPASS_RS_GIT_SHA");
    let upstream_version = env!("LPASS_UPSTREAM_VERSION");
    let upstream_sha = env!("LPASS_UPSTREAM_SHA");
    let rustc_version = env!("LPASS_RUSTC_VERSION");
    let project_url = env!("CARGO_PKG_REPOSITORY");
    format_version_string(
        version,
        sha,
        upstream_version,
        upstream_sha,
        rustc_version,
        project_url,
    )
}

fn format_version_string(
    version: &str,
    sha: &str,
    upstream_version: &str,
    upstream_sha: &str,
    rustc_version: &str,
    project_url: &str,
) -> String {
    format!(
        "LastPass CLI (Rust) v{version} ({sha}) (based on lastpass-cli {upstream_version}, upstream {upstream_sha}; {rustc_version}; {project_url})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_version_matches_package_version() {
        assert_eq!(generated_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn format_version_string_places_package_version_and_sha_separately() {
        let package_version = env!("CARGO_PKG_VERSION");
        let out = format_version_string(
            package_version,
            "abcdef123456",
            "v1.2.3",
            "123456abcdef",
            "rustc 1.90.0",
            "https://example.invalid/repo",
        );

        assert!(out.starts_with(&format!(
            "LastPass CLI (Rust) v{package_version} (abcdef123456)"
        )));
        assert!(out.contains("based on lastpass-cli v1.2.3"));
        assert!(out.contains("upstream 123456abcdef"));
        assert!(out.contains("rustc 1.90.0"));
        assert!(out.contains("https://example.invalid/repo"));
    }
}
