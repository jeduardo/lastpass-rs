# Task 07: Implement `share` Command Family

Status: `todo`

Objective:
- Implement `share` subcommands with strict parity to C behavior, options, and output formats.

Source-of-truth references:
- `lastpass-cli/cmd-share.c`

Scope:
- Subcommands: `userls`, `useradd`, `usermod`, `userdel`, `create`, `rm`, `limit`.
- Shared option parsing (`--sync`, `--color`, permission flags, list mode flags).
- Share lookup and error behavior.
- Display and mutation behavior parity for user and limits operations.

Out of scope:
- Generic environment parity not directly needed by share path (Task 08).

Dependencies:
- Task 01
- Task 02

Implementation steps:
1. Add command module and wire dispatch.
2. Implement shared parser and subcommand routing.
3. Implement each subcommand path and server interactions.
4. Add parity tests for parsing, usage errors, and representative success paths.

Acceptance criteria:
- `lpass share` is no longer stubbed.
- Help/usage and subcommand behavior match C conventions.
- Automated tests cover option matrix and common operations.
