# Task 12: Remove Test-Mode Business Branches

Status: `todo`

Objective:
- Eliminate runtime business-logic divergence driven by test/mock mode while preserving the existing ability to test the CLI without live LastPass network access.

Source-of-truth references:
- C command paths in `lastpass-cli/`
- Rust runtime seams in:
  - `src/http.rs`
  - `src/commands/login.rs`
  - `src/commands/data.rs`
  - `src/commands/import.rs`
  - `src/commands/sync.rs`

Problem statement:
- The Rust CLI currently uses the Rust-only `LPASS_HTTP_MOCK=1` environment variable to change business behavior in production code paths.
- This is broader than transport mocking:
  - `http.rs` swaps the HTTP transport
  - `data.rs` swaps blob/session/key behavior and queue behavior
  - `login.rs` skips the normal post-login blob fetch path
  - `import.rs` bypasses the upload path and mutates the blob directly
  - `sync.rs` can succeed without normal credentials in mock mode
- These are useful test shortcuts, but they make tests exercise different command logic than the normal runtime path.

Scope:
- Move mock/test decisions to the edges of the system rather than command logic.
- Refactor commands so the same business path can be exercised in tests through injected clients/stores or equivalent stable seams.
- Preserve upstream C parity and existing user-facing behavior.

Out of scope:
- Adding new features, flags, or env vars.
- Modifying `lastpass-cli/`.
- Removing the Rust mock transport entirely.

Dependencies:
- Tasks 01-11

Implementation rules:
- Do not add new `#[cfg(test)]` business branches.
- Do not add new test-only env vars or runtime shortcuts.
- If a path is hard to test, refactor toward reusable production seams instead of adding test-only behavior.
- Keep `LPASS_HTTP_MOCK` as a Rust-only testing aid only where it selects mock transport/input sources, not where it changes command semantics.

Implementation steps:
1. Audit all `LPASS_HTTP_MOCK` branches in production modules and classify them as:
   - transport/input selection
   - business-logic divergence
2. Keep transport selection in `http.rs`, but remove command-level business shortcuts from:
   - `login`
   - `data`
   - `import`
   - `sync`
3. Introduce production-useful seams for:
   - blob/session persistence
   - upload execution
   - blob fetching after login
4. Rewrite tests to use those seams through normal command behavior instead of mock-only code paths.
5. Re-run parity and coverage gates until the new paths are covered without reintroducing test-mode logic branches.

Acceptance criteria:
- No command/business module changes behavior solely because `LPASS_HTTP_MOCK=1`.
- Tests can still cover command flows without live network access.
- HTTP mocking remains possible through normal production seams.
- Required gates are green:
  - `cargo test --locked --all-targets`
  - `cargo test-upstream`
  - `cargo coverage`
  - `act -j test --container-architecture linux/arm64`
  - `act -j coverage --container-architecture linux/arm64`
