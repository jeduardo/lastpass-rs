# Task 02: Blob Sync Semantics and Share-Aware Data Model

Status: `done`

Objective:
- Implement C-like blob loading semantics (`--sync` and auto-sync TTL) and extend the model to represent shares/read-only metadata needed for parity.

Source-of-truth references:
- `lastpass-cli/blob.c` (`blob_load`, `auto_sync_time`)
- `lastpass-cli/blob.h` (`share`, readonly flags, share list in blob)

Scope:
- Refactor blob loading to take explicit sync mode (`auto|now|no`) and honor it.
- Implement `LPASS_AUTO_SYNC_TIME` freshness window behavior.
- Extend Rust blob parsing/storage structures to carry share metadata used by commands.
- Wire share metadata into command read/write paths where needed.

Out of scope:
- Full `share` command implementation (Task 07).

Dependencies:
- Task 01

Implementation steps:
1. Change `load_blob` API to accept sync mode.
2. Add TTL-based auto-sync behavior equivalent to C.
3. Add share metadata in blob structs and parser outputs.
4. Update affected commands to use share-aware data and sync-aware loading.
5. Add unit/integration tests for sync mode and share parsing behavior.

Acceptance criteria:
- Commands respect `--sync=auto|now|no` as C does.
- `LPASS_AUTO_SYNC_TIME` controls cache freshness in auto mode.
- Share/read-only metadata is available to command logic.
- Tests cover sync and share model paths.
