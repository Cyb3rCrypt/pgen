# Contributing to pgen

All contributors — maintainers and one-time patch authors alike — must follow
these rules. The CI pipeline enforces what it can; code review enforces the rest.

---

## Table of Contents

1. [Branching Model](#branching-model)
2. [Branch Naming](#branch-naming)
3. [Commit Messages](#commit-messages)
4. [Pull Requests](#pull-requests)
5. [Releasing](#releasing)
6. [Code Style](#code-style)
7. [Quick Reference](#quick-reference)

---

## Branching Model

This project uses **trunk-based development** with one permanent branch:

| Branch | Purpose | Direct push? |
|--------|---------|-------------|
| `main` | Always releasable. Tagged commits trigger CI releases. | Maintainers only for hotfixes; otherwise via PR |

All development happens on short-lived feature branches that are merged back
into `main` via pull request. There is no long-lived `develop` branch.

> **Rule:** `main` must always compile, pass all tests, and be safe to tag.

---

## Branch Naming

### Format

```
<type>/<scope>
```

- **`<type>`** — one of the prefixes in the table below (lowercase).
- **`<scope>`** — a short, lowercase, hyphen-separated description of the work.
  If the work is tracked by a GitHub issue, prefix the scope with the issue
  number: `<issue-number>-<description>`.

### Types

| Type | When to use | Example |
|------|-------------|---------|
| `feat` | Adding a new user-facing feature | `feat/42-add-passphrase-mode` |
| `fix` | Fixing a bug in existing behaviour | `fix/37-off-by-one-min-length` |
| `hotfix` | Urgent patch applied directly to `main` | `hotfix/cvss-high-entropy-leak` |
| `chore` | Maintenance: deps, CI, build, toolchain | `chore/bump-rand-0.11` |
| `docs` | Documentation only, no production code change | `docs/improve-cli-examples` |
| `test` | Adding or fixing tests, no production code change | `test/rejection-sampling-edge-cases` |
| `refactor` | Code restructuring with no behaviour change | `refactor/extract-config-validation` |
| `perf` | Performance improvement with no behaviour change | `perf/reduce-pool-allocations` |
| `release` | Release preparation (version bump + changelog) | `release/1.2.0` |

### Rules

1. **All lowercase.** No uppercase letters anywhere in a branch name.
2. **Hyphens only.** Use `-` as the word separator; never underscores or spaces.
3. **No slashes except the type separator.** `feat/foo` is valid; `feat/foo/bar` is not.
4. **Keep it short.** The scope should be readable at a glance — aim for 3–5 words maximum.
5. **No personal identifiers.** Branch names are about the work, not the author.
   `feat/vikram-new-flag` → `feat/add-verbose-flag`.
6. **Delete after merge.** Stale branches are noise. Delete the remote branch
   when the PR is merged (GitHub can do this automatically).

### Anti-patterns

| Bad | Why | Good |
|-----|-----|------|
| `my-changes` | No type prefix, not descriptive | `fix/33-symbol-set-dedup` |
| `Feature/NewFlag` | Mixed case, wrong separator style | `feat/add-no-symbol-flag` |
| `wip` | Meaningless | `feat/15-count-flag` |
| `fix-stuff` | No type prefix | `fix/clamp-length-warning` |
| `main2` | Shadows the permanent branch name | use a descriptive `feat/…` or `chore/…` |

---

## Commit Messages

This project follows the [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/) specification.
Conventional Commits keep the history readable and drive automated changelog
generation.

### Format

```
<type>(<optional scope>): <short imperative summary>

[optional body]

[optional footers]
```

### Rules

- **First line ≤ 72 characters.**
- **Use the imperative mood** in the summary: "add flag" not "added flag" nor "adds flag".
- **No period** at the end of the summary line.
- **Blank line** between the summary and any body.
- **Body** wraps at 80 characters and explains *what* and *why*, not *how*.
- **Breaking changes** are indicated by `!` after the type/scope, and/or a
  `BREAKING CHANGE:` footer.

### Types (mirror branch types)

| Type | SemVer impact | Changelog section |
|------|--------------|-------------------|
| `feat` | MINOR | Features |
| `fix` | PATCH | Bug Fixes |
| `hotfix` | PATCH | Bug Fixes |
| `perf` | PATCH | Performance |
| `refactor` | none | — |
| `test` | none | — |
| `docs` | none | — |
| `chore` | none | — |
| `build` | none | — |
| `ci` | none | — |
| `feat!` / `fix!` | MAJOR | ⚠ Breaking Changes |

### Examples

```
feat(cli): add --no-symbol flag for symbol exclusion

Closes #42. Some deployments prohibit symbols in passwords; this
flag allows users to opt out of the default symbol set without
having to omit --symbol (which was never included by default anyway).
```

```
fix: clamp --length to MIN_LENGTH instead of hard erroring

Silently accepting lengths below 10 produced weak passwords without
feedback. The previous hard error was overly strict for scripted use.
Clamping with a stderr warning is the right trade-off.
```

```
chore: bump rand 0.10 → 0.11

Updates IndexedRandom import path per upstream rename. No behaviour
change.
```

```
feat!: require at least one character set flag

BREAKING CHANGE: previously, omitting all flags generated an
uppercase+lowercase password by default. Now the caller must be
explicit. Users relying on the default must add no flags — behaviour
is unchanged — but scripts that depended on the old default message
format will need updating.
```

---

## Pull Requests

1. **Open against `main`.** There is no separate integration branch.
2. **One logical change per PR.** Mix neither unrelated fixes nor
   reformatting with feature work — it makes review harder and bisection
   harder.
3. **Title follows Conventional Commits format.** The PR title becomes the
   squash-merge commit message: `feat(cli): add --no-symbol flag`.
4. **All CI checks must pass** before requesting review.
5. **Self-review first.** Read your own diff before asking someone else to.
6. **Address review comments with new commits** during review, then squash on
   merge. Do not force-push during active review.
7. **Reference issues.** Use GitHub keywords in the PR body:
   `Closes #42`, `Fixes #15`.

### Merge strategy

| Scenario | Strategy |
|----------|----------|
| Single-commit PR | Merge commit or squash (either is fine) |
| Multi-commit PR with clean, atomic commits | Merge commit — preserves history |
| Multi-commit PR with messy/WIP commits | Squash merge — produces one clean commit |

> Rebase-merge is **not** used. It rewrites SHAs, which makes `git bisect`
> and blame harder to reason about.

---

## Releasing

The full release runbook is in [doc/RELEASING.md](doc/RELEASING.md).

**Summary of the happy path:**

1. Create a `release/<version>` branch from `main`.
2. Bump the version in `Cargo.toml`; run `cargo build --release` to update `Cargo.lock`.
3. Commit: `chore: bump version to v<version>`
4. Open a PR → merge into `main`.
5. Tag the merge commit: `git tag v<version>`
6. Push tag: `git push origin v<version>`
7. CI builds all targets and publishes the GitHub Release automatically.

> Tags that match `v*.*.*` are the **only** release trigger.
> Never push a `v*.*.*` tag to a commit that hasn't passed CI on `main`.

---

## Code Style

All style checks run in CI. A PR with failing checks will not be merged.

| Tool | Command | What it enforces |
|------|---------|-----------------|
| `rustfmt` | `cargo fmt --check` | Canonical Rust formatting |
| `clippy` | `cargo clippy --all-features -- -D warnings` | Lints (all + pedantic + nursery + cargo) |
| `cargo-audit` | `cargo audit` | Known vulnerability advisories |

Run everything locally before pushing:

```sh
cargo fmt
cargo clippy --all-features -- -D warnings
cargo test --all-features
cargo audit
cargo deny check
```

No `#[allow(...)]` attributes may be added without a comment explaining why
the lint is a false positive for this specific case.

---

## Quick Reference

```
Branch format:   <type>/<issue-number?>-<short-description>
Commit format:   <type>(<scope>?): <imperative summary>
Tag format:      v<MAJOR>.<MINOR>.<PATCH>
Merge target:    main (always)
Release trigger: git push origin v<version>
```

### Branch type → commit type mapping

| Branch prefix | Commit type | SemVer bump |
|---------------|-------------|-------------|
| `feat/`       | `feat`      | MINOR       |
| `fix/`        | `fix`       | PATCH       |
| `hotfix/`     | `hotfix`    | PATCH       |
| `chore/`      | `chore`     | none        |
| `docs/`       | `docs`      | none        |
| `test/`       | `test`      | none        |
| `refactor/`   | `refactor`  | none        |
| `perf/`       | `perf`      | PATCH       |
| `release/`    | `chore`     | none        |
