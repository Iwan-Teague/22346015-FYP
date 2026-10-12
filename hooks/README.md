# Commit-time sensitive check

`pre-commit` scans staged additions for personal paths, session logs and
credentials, then asks before every commit.

## Enable (once per clone)

```
git config core.hooksPath hooks
```

## Private patterns (stay local, never committed)

Create `hooks/sensitive.local` (git-ignored) with one regex per line, e.g.:

```
jim|buckley
transcripts/
```

Lines matching these are flagged on top of the built-in checks.

## Bypass

```
git commit --no-verify
```
