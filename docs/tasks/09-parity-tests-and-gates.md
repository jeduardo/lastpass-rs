# Task 09: Parity Test Expansion and Merge Gates

Status: `done`

Objective:
- Ensure parity work remains stable over time with explicit tests and release gates.

Source-of-truth references:
- Rust tests under `tests/`
- upstream shell tests under `lastpass-cli/test/`

Scope:
- Add parity-focused tests for all newly implemented command paths.
- Expand top-level compatibility coverage where current upstream shell tests do not cover new behavior.
- Define merge gate checks for parity-sensitive changes.

Out of scope:
- Feature implementation itself (covered by tasks 01-11).

Dependencies:
- Tasks 01-11

Implementation rules:
- Treat `lastpass-cli/` as read-only reference code.
- Do not rely on test-only business logic branches to validate parity.
- If production behavior is hard to exercise without `#[cfg(test)]`, test-only env switches, or similar directives, refactor the production code so the same behavior can be tested through normal inputs and stable seams instead.

Parity coverage matrix:
- Task 01 foundation/env/CLI parsing:
  [tests/cli_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_integration.rs),
  [tests/cli_help.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_help.rs),
  [tests/cli_option_color_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_option_color_parity.rs),
  [src/cli.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/cli.rs),
  [src/lpenv.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/lpenv.rs)
- Task 02 blob/session/share data model:
  [src/blob.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/blob.rs),
  [src/session.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/session.rs),
  downstream integration coverage in [tests/share_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/share_integration.rs),
  [tests/add_edit_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/add_edit_parity.rs),
  and [tests/mv_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/mv_parity.rs)
- Task 03 show parity:
  [tests/show_compat.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/show_compat.rs),
  [tests/cli_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_integration.rs),
  [tests/command_coverage.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/command_coverage.rs)
- Task 04 generate parity:
  [tests/cli_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_integration.rs),
  [tests/command_coverage.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/command_coverage.rs),
  [src/commands/generate.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/generate.rs)
- Task 05 sync/import/export parity:
  [tests/cli_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_integration.rs),
  [tests/command_coverage.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/command_coverage.rs),
  [src/commands/import.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/import.rs),
  [src/commands/export.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/export.rs),
  [src/commands/sync.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/sync.rs)
- Task 06 passwd parity:
  [tests/task06_public_coverage.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/task06_public_coverage.rs),
  [tests/password_prompt.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/password_prompt.rs),
  [src/commands/passwd.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/passwd.rs)
- Task 07 share parity:
  [tests/share_integration.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/share_integration.rs),
  [src/commands/share_tests.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/share_tests.rs)
- Task 08 env/prompt/clipboard/logging parity:
  [tests/password_prompt.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/password_prompt.rs),
  [tests/password_public.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/password_public.rs),
  [tests/add_edit_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/add_edit_parity.rs),
  [src/password/mod.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/password/mod.rs),
  [src/logging.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/logging.rs),
  [src/commands/clipboard.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/clipboard.rs)
- Task 10 shared-folder move parity:
  [tests/mv_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/mv_parity.rs),
  [src/commands/mv/tests.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/mv/tests.rs),
  [src/commands/data/tests.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/commands/data/tests.rs)
- Task 11 strict option/color parity:
  [tests/cli_option_color_parity.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_option_color_parity.rs),
  [tests/cli_help.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/tests/cli_help.rs),
  [src/terminal.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/terminal.rs),
  [src/cli.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/cli.rs)

Upstream shell gate:
- [src/bin/test-upstream.rs](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/src/bin/test-upstream.rs) runs the shell compatibility suite via [scripts/run-upstream-shell-tests.sh](/Users/jeduardo/src/github.com/jeduardo/lastpass-rs/scripts/run-upstream-shell-tests.sh).
- The submodule test corpus remains unchanged; Rust-only parity coverage stays in top-level Rust tests.

Implementation steps:
1. Add direct automated coverage for each parity task through unit tests, integration tests, or the upstream shell wrapper.
2. Fill any remaining user-visible parity gaps with top-level Rust integration tests instead of submodule edits.
3. Enforce documented gate commands in CI and local workflow notes.
4. Ensure local `act` runs are meaningful gates by skipping external uploads when running under `act`.

Acceptance criteria:
- All parity tasks have direct automated test coverage.
- Required gate commands are green:
  - `cargo test --locked --all-targets`
  - `cargo test-upstream`
  - `cargo coverage`
  - `act -j test --container-architecture linux/arm64`
  - `act -j coverage --container-architecture linux/arm64`
- Coverage remains at or above 80%.
