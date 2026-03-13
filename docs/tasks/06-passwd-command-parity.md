# Task 06: Implement `passwd` Command

Status: `done`

Objective:
- Implement `passwd` in Rust with behavior equivalent to C, including re-encryption progress, server interaction, and forced logout.

Source-of-truth references:
- `lastpass-cli/cmd-passwd.c`
- related endpoint and crypto flows in `lastpass-cli/`

Scope:
- Master password change flow with current-password verification.
- New password validation and confirmation flow.
- Re-encryption and upload sequence.
- Session termination on success.

Out of scope:
- `share` command family (Task 07).

Dependencies:
- Task 01
- Task 02

Implementation steps:
1. Implement command parser and interactive prompt flow.
2. Implement re-encryption workflow and required API wiring.
3. Implement success/failure messaging and logout behavior.
4. Add command tests for success path and major failure conditions.

Acceptance criteria:
- `lpass passwd` is no longer stubbed.
- Behavior and output structure match C for major paths.
- Unit/integration tests cover prompt and API error paths.

Implementation notes:
- Added full `passwd` command flow in `src/commands/passwd.rs`.
- Added pwchange XML parsing in `src/xml.rs`.
- Added private-key/RSA/hash helpers needed for master-password rotation in `src/crypto.rs`.
- Extended the mock HTTP transport to cover `getacctschangepw` and `updatepassword`.
- Added Rust integration coverage for `passwd`.

Verification:
- `cargo test --locked --all-targets`
- `cargo llvm-cov --workspace --all-targets --json --output-path coverage/full.json --ignore-filename-regex 'src/bin/test-upstream.rs$'`
- `./scripts/run-upstream-shell-tests.sh`
- `act -j test --container-architecture linux/arm64`
