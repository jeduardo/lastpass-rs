# LastPass Rust Parity Task Board

Status legend:
- `todo`: not started
- `in_progress`: actively being implemented
- `blocked`: waiting on a dependency
- `done`: merged with tests passing

Execution order:
1. `01-foundation-alias-env-option-parsing.md` (`todo`)
2. `02-blob-sync-and-shares-data-model.md` (`todo`)
3. `03-show-command-parity.md` (`todo`)
4. `04-generate-command-parity.md` (`todo`)
5. `05-sync-import-export-parity.md` (`todo`)
6. `06-passwd-command-parity.md` (`todo`)
7. `07-share-command-parity.md` (`todo`)
8. `08-env-prompt-clipboard-logging-parity.md` (`todo`)
9. `09-parity-tests-and-gates.md` (`todo`)

Global rules for every task:
- Match behavior and options from `lastpass-cli/` exactly unless explicitly documented.
- Keep changes incremental and testable.
- Add or update tests in the same change.
- Keep project coverage at or above 80%.
- Run:
  - `cargo test`
  - `./scripts/run-upstream-shell-tests.sh`
