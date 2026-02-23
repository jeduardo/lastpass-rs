# Task 03: `show` Command Full Parity

Status: `todo`

Objective:
- Close remaining `show` gaps: regex/fixed searches, multi-match behavior, clipboard, attachments, and strict flag behavior.

Source-of-truth references:
- `lastpass-cli/cmd-show.c`
- `lastpass-cli/cmd.c` matching helpers

Scope:
- Implement `--basic-regexp/-G` and `--fixed-strings/-F` search modes.
- Implement C-like multi-match handling and `--expand-multi/-x`.
- Implement `--clip` output-to-clipboard flow.
- Implement `--attach` handling and related `--quiet` behavior.
- Preserve current JSON and formatting behaviors where already compatible.

Out of scope:
- Clipboard env implementation details beyond what `show` needs (Task 08 deep parity).

Dependencies:
- Task 01
- Task 02

Implementation steps:
1. Rework matching pipeline to support exact/regex/fixed modes.
2. Implement C-like multi-match output and exit behavior.
3. Add attachment lookup/output path with quiet flag behavior.
4. Add clipboard output path for selected values.
5. Add dedicated parity tests for each option combination.

Acceptance criteria:
- `show` options and outputs match C for implemented paths.
- `show` no longer silently ignores parity-critical flags.
- New tests cover regex/fixed, multi-match, clip, and attach cases.
