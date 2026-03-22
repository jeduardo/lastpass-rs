# Task 11: Strict Option Parsing and Color Output Parity

Status: `done`

Objective:
- Close the remaining cross-cutting CLI compatibility gaps around getopt-style parsing, help/usage behavior, and ANSI color handling.

Source-of-truth references:
- `lastpass-cli/lpass.c`
- `lastpass-cli/cmd.c`
- `lastpass-cli/cmd.h`
- `lastpass-cli/terminal.c`
- `lastpass-cli/util.c`
- command-specific C files for any command whose help or error path still differs

Scope:
- Match top-level `--help`, `--version`, and unknown-option handling to the C client.
- Match command-level invalid option, missing argument, and wrong-arity handling to the C client's getopt/die_usage conventions.
- Audit usage/help text drift where Rust currently advertises or formats command usage differently from the C client.
- Align user-facing error/warning output with C-style terminal formatting, including color stripping on non-TTY stdout/stderr and color-preserving output in `always` mode.
- Add parity tests that exercise both stdout and stderr color behavior and invalid option handling through public CLI paths.

Out of scope:
- New flags, aliases, output themes, or diagnostics that do not exist in the C client.
- Command-specific feature work already covered by Tasks 01-10.

Dependencies:
- Task 01
- Task 03
- Task 08

Implementation steps:
1. Audit top-level CLI dispatch and each command wrapper against `lpass.c`, `cmd.c`, `cmd.h`, and `util.c`.
2. Identify remaining places where Rust still returns generic lowercase `error:` output or permissive parsing instead of C-style usage/error behavior.
3. Centralize any shared formatting or parsing helpers needed to keep command behavior consistent without adding non-C features.
4. Add CLI-focused regression tests for unknown flags, missing flag values, wrong positional arity, help/version output, and non-TTY color stripping on both stdout and stderr.
5. Update docs after the remaining cross-cutting TODOs are resolved.

Acceptance criteria:
- Global and command-level option parsing behavior matches the C client closely enough to remove the remaining documented parity TODOs.
- User-facing diagnostics follow the C color/TTY rules on both stdout and stderr.
- No new flags or fallback behaviors are introduced; the task is strictly parity cleanup.

Implemented:
- Routed command-wrapper failures through shared terminal-aware `Error:` / `Usage:` rendering so stderr follows the same color rules as stdout.
- Aligned top-level warning formatting and `mv` / `import` displayed usage text with the C client while preserving their actual supported parsing behavior.
- Added public CLI coverage for non-TTY stderr stripping, `--color=always`, saved-environment warning rendering, and the `mv` / `import` usage/help output drift.
- Added unit coverage for the top-level unknown-flag dispatch path, alias read-error fallback, and warning/usage formatter helpers.

Verification:
- `cargo test --locked --all-targets`
- `cargo llvm-cov --workspace --all-targets --json --output-path coverage/task11.json --ignore-filename-regex 'src/bin/test-upstream.rs$'`
- `act -j test --container-architecture linux/arm64`
- `act -j coverage --container-architecture linux/arm64`
