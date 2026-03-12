#![forbid(unsafe_code)]

pub fn generated_version() -> &'static str {
    env!("LPASS_RS_VERSION")
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
    fn generated_version_is_timestamp_shaped() {
        let version = generated_version();
        assert_eq!(version.len(), 14);
        assert!(version.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn format_version_string_places_timestamp_and_sha_separately() {
        let out = format_version_string(
            "20260312203849",
            "abcdef123456",
            "v1.2.3",
            "123456abcdef",
            "rustc 1.90.0",
            "https://example.invalid/repo",
        );

        assert!(out.starts_with("LastPass CLI (Rust) v20260312203849 (abcdef123456)"));
        assert!(out.contains("based on lastpass-cli v1.2.3"));
        assert!(out.contains("upstream 123456abcdef"));
        assert!(out.contains("rustc 1.90.0"));
        assert!(out.contains("https://example.invalid/repo"));
    }
}
