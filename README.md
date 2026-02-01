# lastpass-rs

[![CI](https://github.com/jeduardo/lastpass-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jeduardo/lastpass-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jeduardo/lastpass-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/jeduardo/lastpass-rs)

A Rust rewrite of the LastPass CLI (`lpass`), with a strong focus on drop-in compatibility with the original C client.

> [!WARNING] > **Alpha software:** this project is under heavy active development.
> Expect breaking changes between commits, missing features, and partial behavior parity.
> Do not rely on it as your only way to access production vault data yet.
> This code was not audited for security.
> **Use at your own risk**

## Status

This project is in active development. The goal is:

- full feature parity with `lastpass-cli`
- same command interface (flags/options)
- same config and environment variable behavior
- safe Rust only (`#![forbid(unsafe_code)]`)
- Cargo-only build and test workflow

The original C implementation is kept in `lastpass-cli/` and is used as the reference for compatibility.

## Current command coverage

Implemented (working, with ongoing parity improvements):

- `login`
- `status`
- `ls`
- `show`
- `add`
- `edit`
- `duplicate`
- `generate`
- `export`

Planned / not fully implemented yet:

- `logout`
- `passwd`
- `mv`
- `rm`
- `sync`
- `import`
- `share`

## Implementation status

Audit source of truth:

- `lastpass-cli/cmd-login.c`
- `lastpass-cli/cmd-status.c`
- `lastpass-cli/cmd-ls.c`
- `lastpass-cli/cmd-show.c`
- `lastpass-cli/cmd-add.c`
- `lastpass-cli/cmd-edit.c`
- `lastpass-cli/cmd-duplicate.c`
- `lastpass-cli/cmd-generate.c`
- `lastpass-cli/cmd-export.c`

Per-command checklist:

- `login`

  - default flow and success color output: :white_check_mark:
  - `--color`: :white_check_mark:
  - `--trust`: TODO
  - `--plaintext-key` confirmation UX parity (`--force` behavior): TODO

- `status`

  - default output and color: :white_check_mark:
  - `--quiet`, `--color`: :white_check_mark:

- `ls`

  - default list output: :white_check_mark:
  - `--color`: :white_check_mark:
  - `--long/-l`, `-m`, `-u` exact behavior parity: TODO
  - `--format/-f`: TODO
  - positional `GROUP` filtering (including `(none)`): TODO
  - tree/shared-folder rendering parity with C client: TODO

- `show`

  - default output, `--json`, `--all|--username|--password|--url|--notes|--field|--id|--name`: :white_check_mark: (basic parity)
  - `--color`: :white_check_mark:
  - `--attach`, `--clip`: TODO
  - `--basic-regexp/-G`, `--fixed-strings/-F`, `--expand-multi/-x`: TODO
  - `--title-format/-t`, `--format/-o`: TODO
  - strict multi-match behavior/output parity: TODO

- `add`

  - `--non-interactive` path: :white_check_mark: (basic parity)
  - interactive mode parity: TODO
  - exact `--username|--password|--url|--notes|--field|--app` semantics: TODO
  - `--note-type`: :white_check_mark: (basic parity)

- `edit`

  - `--non-interactive` path: :white_check_mark: (basic parity)
  - interactive mode parity: TODO
  - exact option semantics/validation parity: TODO
  - C behavior when entry does not exist (create path): TODO

- `duplicate`

  - default behavior, `--sync`, `--color`: :white_check_mark: (basic parity)

- `generate`

  - default generation path: :white_check_mark: (partial parity)
  - short option parity (`-U`, `-L`): TODO
  - `--clip`: TODO
  - symbol set parity (`default` vs `--no-symbols`): TODO

- `export`

  - default export and `--fields`: :white_check_mark: (basic parity)
  - `--fields` validation parity: TODO
  - protected-entry reprompt/auth parity: TODO

- Cross-cutting
  - strict C-like option parsing errors for unknown/invalid flags: TODO
  - exact color semantics parity for all implemented commands: TODO

## Build

Requires the latest stable Rust toolchain.

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Binary path:

- debug: `target/debug/lpass`
- release: `target/release/lpass`

## Usage

```bash
# Show help
cargo run -- --help

# Login
cargo run -- login you@example.com

# Vault status
cargo run -- status

# List entries
cargo run -- ls

# Show entry
cargo run -- show "personal/example"
```

## Environment

Compatibility with the C client is a core requirement. Existing behavior around config/env is being preserved, including support for common variables such as:

- `LPASS_HOME`
- `LPASS_ASKPASS`
- `LPASS_AGENT_DISABLE`
- `LPASS_AGENT_TIMEOUT`

## Testing

Rust tests:

```bash
cargo test
```

Coverage report (Codecov-compatible LCOV):

```bash
cargo coverage
```

This uses `cargo-llvm-cov` and writes `coverage/lcov.info`, which can be uploaded to Codecov.

Optional local HTML report:

```bash
cargo coverage-html
```

Upstream compatibility shell tests:

```bash
cargo test-upstream
```

You can pass individual test names to run a subset:

```bash
cargo test-upstream -- test_login test_ls
```

## Project goals and fidelity rules

- Commands should match the C client behavior before being considered complete.
- Colors, output shape, flags, and side effects should follow the reference implementation.
- Any intentional deviation should be documented.

## AI-assisted development

This project is built with support from AI tooling as part of the development workflow. All generated changes are reviewed and validated with compilation and tests.

## Credits

- [dynacylabs/lastpass-py](https://github.com/dynacylabs/lastpass-py) for inspiration.
- [Michael-F-Bryan/lastpass](https://github.com/Michael-F-Bryan/lastpass) for inspiration.
- [LastPass/lastpass-cli](http://github.com/Lastpass/lastpass-cli/) for crashing so much (and motivating this rewrite).

## License

GPL-2.0-or-later. See `LICENSE`.
