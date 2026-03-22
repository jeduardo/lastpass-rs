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
- `LPASS_PINENTRY`, `LPASS_DISABLE_PINENTRY`, `TERM`, and `DISPLAY` now follow the upstream prompt precedence and pinentry protocol.
- `LPASS_CLIPBOARD_COMMAND` now uses the C-compatible shell execution path, including empty-but-set override handling.
- `LPASS_LOG_LEVEL` now writes `lpass.log` through the standard config path.
- Editor workflows now use secure tempdir selection shared by `add` and `edit`.
