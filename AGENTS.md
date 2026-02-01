# AGENTS.md

## Project goals
- Full rewrite in Rust with feature parity for the CLI.
- Drop-in replacement: same interface, same config locations/behavior.
- Use safe Rust only.
- Cargo-only build (no other build systems).
- Target the most recent stable Rust.
- Keep the existing C files for now.
- Keep the existing shell tests for now, but update them as needed.

## Testing requirements
- Ensure code always compiles and tests always run.
- If there are no tests for new functionality, add tests.
- Aim for at least 80% test coverage.
- Every new feature implementation must include unit tests in the same change.
- Do not consider a feature complete unless tests are added/updated and passing.
- Keep project test coverage at or above 80%; if a change risks dropping below this, add coverage before finishing.

## UI/UX behavior
- If the C CLI has colored output, mirror that behavior.
- Respect `--color=auto|never|always` flags for commands that support it.
- Default to ANSI-stripped output when not in a TTY (auto mode).

## Development expectations
- Implement features in incremental, testable steps.
- Prefer compatibility with existing CLI behavior, flags, and outputs.

## Fidelity directives (C client parity)
- Before considering a command complete, verify parity against the C implementation for:
  - command behavior and output structure
  - flags/options (including short and long forms)
  - environment variable handling
  - config file names/locations and side effects
- Use `lastpass-cli/` in this repository as the primary reference implementation when validating parity.
- For any command that supports colors in the C client, ensure Rust output uses the same color semantics and formatting defaults.
- Treat the C source as the source of truth for CLI compatibility when behavior is ambiguous.
- If behavior is intentionally different, document the deviation clearly in the change notes.
