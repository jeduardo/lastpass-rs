# Dependabot Low-Risk Auto-Merge Design

## Goal

Automatically enable merging for low-risk Dependabot dependency updates in
`lastpass-rs`, matching the existing policy used by the `terminal-bot`
repository.

## Behavior

- Add `.github/workflows/dependabot-auto-merge.yml`.
- Run on Dependabot pull requests when they are opened, reopened, or updated.
- Run the job only when the pull request author is `dependabot[bot]`.
- Fetch Dependabot update metadata with `dependabot/fetch-metadata@v3`.
- Enable GitHub auto-merge with squash for SemVer patch and minor updates.
- Let the repository's existing required checks determine when an approved
  auto-merge can complete.
- Do not auto-merge major updates or pull requests from other authors.

## Permissions and safety

The workflow grants only `contents: write` and `pull-requests: write`, matching
the permissions needed to enable pull-request auto-merge. It uses
`pull_request_target` so the workflow can access the base repository token
without executing code from the Dependabot branch. The job remains restricted
to Dependabot-authored pull requests, and the merge command uses the pull
request URL supplied by the event.

## Compatibility

The implementation follows the terminal-bot workflow's trigger, metadata,
SemVer policy, and squash-merge behavior. Existing CI workflows and project
build/test behavior are unchanged.

## Verification

- Parse or lint the workflow YAML.
- Review the final diff to confirm only the intended workflow and design
  documentation are changed.
- Run the repository's applicable test/check command if available; workflow
  configuration changes do not add Rust production code or unit-test behavior.
