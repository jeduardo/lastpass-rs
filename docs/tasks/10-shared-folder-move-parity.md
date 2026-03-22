# Task 10: Shared-Folder Move Semantics Parity

Status: `done`

Objective:
- Align `lpass mv` shared-folder behavior with the C client when moving entries into, out of, or between shared folders.

Source-of-truth references:
- `lastpass-cli/cmd-mv.c`
- `lastpass-cli/endpoints-share.c` (`lastpass_share_move`)
- `lastpass-cli/blob.c` (`account_assign_share`, re-encryption path)
- `lastpass-cli/endpoints.c` (`lastpass_update_account`)

Scope:
- Preserve current plain folder rename behavior for non-shared moves.
- Detect when `mv` crosses a share boundary and follow the C special-case flow instead of treating it as a normal local rename.
- Re-encrypt moved entries with the correct key material when share membership changes.
- Send the C-compatible shared-folder move API payload, including `sharedfolderid`, `origsharedfolderid`, and delete-on-move behavior.
- Keep readonly target-share rejection aligned with the C client.
- Add regression coverage for move-into-share, move-out-of-share, share-to-share, and readonly-target cases.

Out of scope:
- New `mv` flags or alternate move syntax.
- Non-`mv` shared-folder editing flows already covered by existing tasks.

Dependencies:
- Task 02
- Task 05
- Task 07

Implementation steps:
1. Audit the current Rust `mv` path against `cmd-mv.c` and identify where share-boundary moves still use the normal update/save flow.
2. Add a Rust equivalent of the C share-transition path, including orig/target share tracking and re-encryption with the correct key.
3. Route cross-share moves through the upstream-style API call instead of local blob-only mutation.
4. Verify blob persistence and queue/upload behavior still match C after a successful move.
5. Add unit and CLI integration tests for the share-boundary matrix and readonly failures.

Acceptance criteria:
- Moving an entry within the same share or plain folder keeps the normal update path.
- Moving an entry into, out of, or between shared folders follows the C special-case behavior.
- Readonly share targets fail with parity-compatible errors.
- No new user-facing flags or behaviors are introduced beyond C parity.

Implemented:
- `mv` now distinguishes same-share/plain moves from share-boundary transitions.
- Cross-share moves use the direct `uploadaccounts` shared-folder move request modeled on the C `lastpass_share_move` path.
- The move payload carries `sharedfolderid`, `origsharedfolderid`, `todelete`, and `recordUrl` parity fields.
- Successful cross-share moves remove the local entry after upload, matching the C client’s blob behavior.
- Regression coverage covers plain moves, same-share moves, share-to-share moves, readonly target rejection, and the shared move request builder/error handling.
