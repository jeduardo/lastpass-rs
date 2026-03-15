# Task 08: Environment, Prompt, Clipboard, and Logging Parity

Status: `done`

Objective:
- Match C handling for environment-driven prompt, clipboard, logging, and tempdir behavior.

Source-of-truth references:
- `lastpass-cli/password.c`
- `lastpass-cli/clipboard.c`
- `lastpass-cli/log.c`
- `lastpass-cli/edit.c`

Scope:
- Prompt stack parity for `LPASS_PINENTRY`, `LPASS_DISABLE_PINENTRY`, and related TTY env use.
- Clipboard command parity for `LPASS_CLIPBOARD_COMMAND` and shell execution behavior.
- Logging parity for `LPASS_LOG_LEVEL` and log file path behavior.
- Tempdir/security env behavior needed by editor workflows (`SECURE_TMPDIR`, `TMPDIR`).

Out of scope:
- Large new UX not present in C client.

Dependencies:
- Task 01
- Task 03
- Task 04

Implementation steps:
1. Extend password prompting to include pinentry/fallback path parity.
2. Implement clipboard command/env behavior used by show/generate.
3. Add log-level-driven logging compatibility paths.
4. Add tempdir env handling used by editor paths.
5. Add tests for env-driven branch behavior.

Acceptance criteria:
- Env vars documented in parity audit are implemented or intentionally documented as deviations.
- `show --clip` and `generate --clip` use parity-compatible clipboard handling.
- Prompt and fallback behavior follows C precedence rules.

Implemented:
- `LPASS_ASKPASS`, `LPASS_PINENTRY`, `LPASS_DISABLE_PINENTRY`, `TERM`, and `DISPLAY` now follow the C prompt precedence and pinentry protocol flow.
- `LPASS_CLIPBOARD_COMMAND` now matches the C command-selection rules, including empty-value handling through `$SHELL -c`.
- `LPASS_LOG_LEVEL` now writes `lpass.log` in the config data path, and the Rust HTTP/upload-queue paths emit the same class of debug lines as upstream.
- `SECURE_TMPDIR` / `TMPDIR` are now used by the editor workflows through a shared secure-temp helper, and Linux uses `/dev/shm` like the C client.

Documented deviation:
- macOS currently honors `SECURE_TMPDIR` and `TMPDIR`, but it does not yet recreate the upstream RAM-disk auto-mount flow from `edit.c`. The runtime behavior is functional and env-compatible, but not byte-for-byte identical on that one platform-specific path.
