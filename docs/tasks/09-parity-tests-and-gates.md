# Task 09: Parity Test Expansion and Merge Gates

Status: `todo`

Objective:
- Ensure parity work remains stable over time with explicit tests and release gates.

Source-of-truth references:
- Rust tests under `tests/`
- upstream shell tests under `lastpass-cli/test/`

Scope:
- Add parity-focused tests for all newly implemented command paths.
- Expand shell-based compatibility coverage where current upstream tests do not cover new behavior.
- Define merge gate checks for parity-sensitive changes.

Out of scope:
- Feature implementation itself (covered by tasks 01-08).

Dependencies:
- Tasks 01-08

Implementation steps:
1. Add test cases for new options/behaviors introduced in each task.
2. Add/adjust upstream shell test wrappers for newly covered commands.
3. Enforce documented gate commands in CI and local workflow notes.

Acceptance criteria:
- All parity tasks have direct automated test coverage.
- Required gate commands are green:
  - `cargo test`
  - `./scripts/run-upstream-shell-tests.sh`
- Coverage remains at or above 80%.
