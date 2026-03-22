# LastPass Rust Parity Task Board

Status legend:
- `todo`: not started
- `in_progress`: actively being implemented
- `blocked`: waiting on a dependency
- `done`: merged with tests passing

Recommended execution order:
1. `01-foundation-alias-env-option-parsing.md` (`done`)
2. `02-blob-sync-and-shares-data-model.md` (`done`)
3. `03-show-command-parity.md` (`done`)
4. `04-generate-command-parity.md` (`done`)
5. `05-sync-import-export-parity.md` (`done`)
6. `06-passwd-command-parity.md` (`done`)
7. `07-share-command-parity.md` (`done`)
8. `08-env-prompt-clipboard-logging-parity.md` (`done`)
9. `10-shared-folder-move-parity.md` (`todo`)
10. `11-strict-option-parsing-and-color-output-parity.md` (`todo`)
11. `09-parity-tests-and-gates.md` (`todo`, final consolidation task)

Global rules for every task:
- Match behavior and options from `lastpass-cli/` exactly unless explicitly documented.
- Keep changes incremental and testable.
- Add or update tests in the same change.
- Keep project coverage at or above 80%.
- Run:
  - `cargo test`
  - `./scripts/run-upstream-shell-tests.sh`
