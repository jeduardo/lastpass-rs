# Task 05: `sync`, `import`, `export` Parity

Status: `todo`

Objective:
- Align `sync`, `import`, and `export` behavior with C client semantics, including protected-entry flows and queue/server behavior.

Source-of-truth references:
- `lastpass-cli/cmd-sync.c`
- `lastpass-cli/cmd-import.c`
- `lastpass-cli/cmd-export.c`

Scope:
- `sync`: match background/non-background behavior and queue semantics.
- `import`: align with C-side upload flow and option handling.
- `export`: parity for field behavior and protected-entry authentication flow.
- Normalize edge-case output formatting differences where parity requires.

Out of scope:
- `passwd` and `share` command implementation (Tasks 06 and 07).

Dependencies:
- Task 01
- Task 02

Implementation steps:
1. Rework `sync` to follow C execution model for queue/background behavior.
2. Rework `import` pipeline to match C upload-oriented behavior.
3. Add protected-entry reprompt/auth handling to `export`.
4. Add tests for sync background mode, import upload path, and export protected entries.

Acceptance criteria:
- `sync`, `import`, and `export` user-visible behavior is C-compatible for supported paths.
- Relevant parity tests and integration tests pass.
