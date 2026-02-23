# Task 04: `generate` Command Full Parity

Status: `todo`

Objective:
- Bring `generate` to C parity for charset behavior, clipboard support, readonly checks, and update semantics.

Source-of-truth references:
- `lastpass-cli/cmd-generate.c`

Scope:
- Implement correct default charset and `--no-symbols` behavior.
- Implement `--clip/-c` behavior.
- Enforce readonly shared-entry restrictions consistently with C.
- Ensure create/update flows match C-side semantics closely.

Out of scope:
- Broad clipboard env compatibility work (Task 08).

Dependencies:
- Task 01
- Task 02

Implementation steps:
1. Replace current password generator with C-equivalent charset selection.
2. Add clipboard path for generated password output.
3. Add readonly guard logic for shared entries.
4. Align update/create mutation flow with parity expectations.
5. Add tests for option behavior, edge cases, and readonly failures.

Acceptance criteria:
- `generate` output length and symbol policy match C.
- `--clip` path works and is tested.
- Readonly shared entries are rejected with parity-compatible behavior.
