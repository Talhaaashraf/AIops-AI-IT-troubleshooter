---
name: qa
description: Run the full QA team on the current changes (or a given scope). Starts the qa-functional, qa-performance, qa-security and qa-e2e agents in parallel and merges their reports into one PASS/FAIL table with deduplicated findings ranked by severity. Report only; never edits code.
argument-hint: "[scope: files, a commit range, or 'all'; default = uncommitted changes]"
---

# QA run

Run every QA specialist on one scope and give the user one merged report. Do not edit project files in this skill.
Fixes happen afterwards, only if the user asks.

## 1. Scope

- With an argument, use it as the scope (paths, a commit range such as `HEAD~3..HEAD`, or `all` for the whole repo).
- Without one, the scope is the uncommitted work: run `git status --short` and `git diff HEAD --stat`, and include
  untracked files.
- Write a short scope brief: the changed files, what the change is for (from the diff and `task.md`), and any
  known context the agents need (for example findings already fixed, or tests known to fail before the change).

## 2. Fan out

In a **single message**, start all four agents with the Agent tool, each with the same scope brief:

| subagent_type | focus |
|---|---|
| `qa-functional` | unit suite, regressions vs pre-existing failures, state machines, error paths, untested branches |
| `qa-performance` | event-loop blocking, locks across I/O, scans/queries, starvation, payload bounds, timings |
| `qa-security` | auth on routes, suggest-only rule, secrets, XSS, path traversal, injection |
| `qa-e2e` | drift between the change and `tests/e2e`, uncovered flows, the server command list |

Tell each one to return its table, its ranked findings (file:line, failure scenario, fix, CONFIRMED/PLAUSIBLE) and
what it could not verify. Wait for all four.

## 3. Merge

- Merge the four tables into one: area | check | PASS/FAIL/NOT RUN | evidence.
- Deduplicate findings that point at the same defect (same file and root cause). Keep the clearest scenario and
  note which agents raised it.
- Before you report a finding, read the cited code yourself. Drop findings the code clearly refutes, and say how
  many you dropped.
- Rank by severity: lost alerts, data loss, security holes and stuck workflows first; then performance; then
  coverage gaps and cleanups.

## 4. Report to the user

1. One-line verdict: **PASS** (no confirmed findings), **PASS WITH NOTES**, or **FAIL**.
2. The merged table.
3. Findings, most severe first, each with file:line, the problem in plain words, the failure scenario and the fix.
4. Pre-existing failures, kept separate from regressions.
5. Server-side commands from qa-e2e that the user still needs to run.
6. What nobody could verify.

End by offering to fix the confirmed findings. Do not start fixing without the user's go-ahead.
