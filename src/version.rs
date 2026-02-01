#![forbid(unsafe_code)]

pub fn version_string() -> String {
    let sha = env!("LPASS_RS_GIT_SHA");
    let upstream_version = env!("LPASS_UPSTREAM_VERSION");
    let upstream_sha = env!("LPASS_UPSTREAM_SHA");
    format!(
        "LastPass CLI v{sha} (based on lastpass-cli {upstream_version}, upstream {upstream_sha})"
    )
}
