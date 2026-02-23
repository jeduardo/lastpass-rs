# Task 01: Foundation (Alias, Saved Env, Strict Option Parsing)

Status: `done`

Objective:
- Align command bootstrap behavior with C for alias expansion, saved environment loading, and strict option parsing.

Source-of-truth references:
- `lastpass-cli/lpass.c` (alias expansion and `env` loading)
- `lastpass-cli/cmd.c` (`parse_sync_string`, `parse_color_mode_string`, `parse_bool_arg_string`)

Scope:
- Load config `env` and inject environment variables before command dispatch.
- Expand command aliases from `alias.<command>` before dispatch.
- Introduce shared parsing helpers for `--sync`, `--color`, and C-style boolean args.
- Remove permissive parsing paths that currently accept malformed values.

Out of scope:
- New command features (`show --attach`, `share`, `passwd`) handled in later tasks.

Dependencies:
- None

Implementation steps:
1. Add bootstrap layer to CLI entry path to load `env` config and expand aliases.
2. Add reusable argument parsing helpers in Rust command core.
3. Update command modules to use shared helpers and reject invalid values uniformly.
4. Add regression tests for alias expansion, env loading, and option parsing errors.

Acceptance criteria:
- `alias.<name>` config behavior matches C for token expansion.
- `env` config lines are loaded similarly to C and bad lines are handled safely.
- Commands reject invalid `--sync`, `--color`, and boolean strings consistently.
- Existing tests and new tests pass.
