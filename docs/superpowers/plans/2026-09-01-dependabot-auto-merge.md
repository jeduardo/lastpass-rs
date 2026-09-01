# Dependabot Low-Risk Auto-Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GitHub Actions workflow that enables squash auto-merge for Dependabot SemVer patch and minor updates after the repository’s required checks pass.

**Architecture:** One narrowly scoped `pull_request_target` workflow will inspect Dependabot metadata and invoke GitHub CLI auto-merge only for Dependabot-authored patch/minor updates. It will use the base repository token and minimal write permissions, while existing CI remains responsible for validation.

**Tech Stack:** GitHub Actions YAML, `dependabot/fetch-metadata@v3`, GitHub CLI (`gh`), existing Rust CI workflows.

---

### Task 1: Add the Dependabot auto-merge workflow

**Files:**
- Create: `.github/workflows/dependabot-auto-merge.yml`

- [ ] **Step 1: Create the workflow with the terminal-bot policy**

Add this exact workflow:

```yaml
name: Dependabot auto-merge

on:
  pull_request_target:
    types:
      - opened
      - reopened
      - synchronize

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-merge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest

    steps:
      - name: Get Dependabot metadata
        id: metadata
        uses: dependabot/fetch-metadata@v3

      - name: Enable auto-merge for patch and minor updates
        if: |
          steps.metadata.outputs.update-type == 'version-update:semver-patch' ||
          steps.metadata.outputs.update-type == 'version-update:semver-minor'
        env:
          GH_TOKEN: ${{ github.token }}
          PR_URL: ${{ github.event.pull_request.html_url }}
        run: gh pr merge --auto --squash "$PR_URL"
```

- [ ] **Step 2: Check the workflow for formatting errors**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 3: Inspect the workflow against the approved requirements**

Run:

```bash
sed -n '1,220p' .github/workflows/dependabot-auto-merge.yml
```

Confirm the file contains all three event types, the Dependabot author guard,
the two minimal write permissions, the metadata action, both patch/minor
conditions, and squash auto-merge.

- [ ] **Step 4: Commit the workflow**

```bash
git add .github/workflows/dependabot-auto-merge.yml
git commit -m "ci: auto-merge low-risk Dependabot updates"
```

### Task 2: Verify repository state and applicable checks

**Files:**
- Verify: `.github/workflows/dependabot-auto-merge.yml`
- Verify: `Cargo.toml`
- Verify: `docs/superpowers/specs/2026-09-01-dependabot-auto-merge-design.md`

- [ ] **Step 1: Validate the final diff and status**

Run:

```bash
git status --short --branch
git diff HEAD^ --check
git show --stat --oneline HEAD
```

Expected: the workflow commit contains only the new workflow, the working tree
is clean, and the diff has no whitespace errors.

- [ ] **Step 2: Run the Rust test suite because it is the project’s applicable CI check**

Run:

```bash
cargo test --locked --all-targets --features test-harness
```

Expected: exit code 0 with all tests passing. This confirms the workflow change
did not disturb the repository’s build/test state.

- [ ] **Step 3: Report the workflow-specific limitation**

Record that GitHub Actions expression evaluation and Dependabot metadata
behavior cannot be fully exercised locally; the workflow’s event filters and
conditions are verified by inspection against the approved terminal-bot
reference, while repository tests validate the unchanged Rust project.
