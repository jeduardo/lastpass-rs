# lastpass-rs

[![CI](https://github.com/jeduardo/lastpass-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jeduardo/lastpass-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jeduardo/lastpass-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/jeduardo/lastpass-rs)

An unofficial Rust rewrite of the LastPass CLI (`lpass`), with a strong focus on drop-in compatibility with the original C client.

  ⚠️ **WARNING** ⚠️ **Alpha software:** 
  This project is under heavy active development.
  Expect breaking changes between commits, missing features, and partial behavior parity.
  Do not rely on it as your only way to access production vault data yet.
  This code was not audited for security.
  **Use at your own risk**

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
- `logout`
- `status`
- `ls`
- `show`
- `add`
- `edit`
- `duplicate`
- `generate`
- `export`
- `mv`
- `rm`
- `sync`
- `import`

Planned / not fully implemented yet:

- `passwd`
- `share`

## Implementation status

Audit source of truth:

- `lastpass-cli/cmd-login.c`
- `lastpass-cli/cmd-logout.c`
- `lastpass-cli/cmd-status.c`
- `lastpass-cli/cmd-ls.c`
- `lastpass-cli/cmd-show.c`
- `lastpass-cli/cmd-add.c`
- `lastpass-cli/cmd-edit.c`
- `lastpass-cli/cmd-duplicate.c`
- `lastpass-cli/cmd-generate.c`
- `lastpass-cli/cmd-export.c`
- `lastpass-cli/cmd-mv.c`
- `lastpass-cli/cmd-rm.c`
- `lastpass-cli/cmd-sync.c`
- `lastpass-cli/cmd-import.c`

Per-command checklist:

- `login`

  - default flow and success color output: :white_check_mark:
  - `--color`: :white_check_mark:
  - `--trust` (trusted ID persistence + login/trust params): :white_check_mark: (basic parity)
  - `--plaintext-key` confirmation UX parity (`--force` behavior): :white_check_mark:

- `status`

  - default output and color: :white_check_mark:
  - `--quiet`, `--color`: :white_check_mark:

- `ls`

  - default list output: :white_check_mark:
  - `--color`: :white_check_mark:
  - `--long/-l`, `-m`, `-u` exact behavior parity: TODO
  - `--format/-f`: :white_check_mark: (basic parity)
  - positional `GROUP` filtering (including `(none)`): TODO
  - tree/shared-folder rendering parity with C client: TODO

- `show`

  - default output, `--json`, `--all|--username|--password|--url|--notes|--field|--id|--name`: :white_check_mark: (basic parity)
  - `--color`: :white_check_mark:
  - `--attach`, `--clip`: TODO
  - `--basic-regexp/-G`, `--fixed-strings/-F`, `--expand-multi/-x`: TODO
  - `--title-format/-t`, `--format/-o`: :white_check_mark: (basic parity)
  - strict multi-match behavior/output parity: TODO

- `logout`

  - default behavior and local session cleanup: :white_check_mark:
  - remote logout flow (`agent_ask` gated, best-effort server call): :white_check_mark:
  - `--force/-f`, `--color`: :white_check_mark:
  - exact interactive prompt text parity: :white_check_mark:

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

- `mv`

  - default move behavior by ID/name: :white_check_mark: (basic parity)
  - `--sync`, `--color`: :white_check_mark:
  - shared-folder move semantics parity: TODO

- `rm`

  - default remove behavior by ID/name: :white_check_mark: (basic parity)
  - `--sync`, `--color`: :white_check_mark:
  - readonly shared-entry delete parity: TODO

- `sync`

  - default path and `--background/-b`: :white_check_mark: (basic parity)
  - `--color`: :white_check_mark:
  - uploader/background queue parity with C client: TODO

- `import`

  - stdin/file CSV input and `--keep-dupes`: :white_check_mark: (basic parity)
  - core header mapping (`url,username,password,extra,name,grouping,fav`): :white_check_mark:
  - full API/upload parity and CSV edge cases: TODO

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

## Prebuilt binaries

Every push to `main` updates a rolling GitHub release tagged `latest` with fresh cross-compiled binaries.

- Release page: [latest](https://github.com/jeduardo/lastpass-rs/releases/tag/latest)

Available targets:

- `lpass-linux-x86_64.tar.gz`
- `lpass-linux-arm64.tar.gz`
- `lpass-macos-x86_64.tar.gz`
- `lpass-macos-arm64.tar.gz`
- `lpass-windows-x86_64.zip`
- `lpass-windows-arm64.zip`

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

Implementation status for environment variables (source audited from `lastpass-cli/` plus Rust-only additions):

| Variable | Purpose | Rust status |
| --- | --- | --- |
| `LPASS_HOME` | Override base config/data/runtime path root. | ✅ Implemented |
| `XDG_DATA_HOME` | XDG data base dir for `lpass` data files. | ✅ Implemented |
| `XDG_CONFIG_HOME` | XDG config base dir for aliases/config. | ✅ Implemented |
| `XDG_RUNTIME_DIR` | XDG runtime dir for sockets/locks/runtime state. | ✅ Implemented |
| `HOME` | Fallback home directory for config path resolution. | ✅ Implemented |
| `LPASS_AGENT_TIMEOUT` | Agent key timeout in seconds (`0` = no timeout). | ✅ Implemented |
| `LPASS_AGENT_DISABLE` | Disable use of the background agent when set to `1`. | ✅ Implemented |
| `LPASS_ASKPASS` | External askpass helper command for password input. | ✅ Implemented |
| `LPASS_AUTO_SYNC_TIME` | Auto-sync freshness window (seconds) for blob cache. | ❌ Not implemented yet |
| `LPASS_PINENTRY` | Pinentry executable override. | ❌ Not implemented yet |
| `LPASS_DISABLE_PINENTRY` | Disable pinentry fallback and use tty prompt path. | ❌ Not implemented yet |
| `LPASS_CLIPBOARD_COMMAND` | Custom clipboard command for clip operations. | ❌ Not implemented yet |
| `LPASS_LOG_LEVEL` | Debug logging verbosity level. | ❌ Not implemented yet |
| `SECURE_TMPDIR` | Secure temp dir override used by editor workflows. | ❌ Not implemented yet |
| `TMPDIR` | Fallback temp dir for secure editing path. | ❌ Not implemented yet |
| `SHELL` | Shell used to execute clipboard command wrappers. | ❌ Not implemented yet |
| `TERM` | TTY type passed to pinentry integration. | ❌ Not implemented yet |
| `DISPLAY` | Display target passed to pinentry integration. | ❌ Not implemented yet |
| `LPASS_HTTP_MOCK` | Rust-only mock HTTP/test mode toggle (`1` enables mock). | ✅ Implemented (Rust extension) |

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
