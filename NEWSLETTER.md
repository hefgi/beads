# Beads v0.57.0 — The Self-Managing Release

**February 23 - March 1, 2026**

Beads v0.57.0 is the largest release since v0.56. With 550 commits, 54 features, and 234 fixes, this release focuses on making Beads self-managing: automatic server management, automatic migration, automatic backup, and automatic hook updates. The system handles its own infrastructure so users can focus on issues.

## Self-Managing Dolt Server

Standalone users no longer need to think about server management. Beads now auto-starts, auto-stops, and auto-recovers the Dolt server:

- **Port collision fallback** — if the configured port is busy, tries the next one
- **Idle monitor** — shuts down the server after inactivity
- **Crash watchdog** — restarts on unexpected exits
- **Circuit breaker** — prevents agent hangs on unresponsive servers

Use `bd dolt start/stop` for manual control, or let Beads handle it automatically.

## Automatic Migration

SQLite users upgrading to v0.57 get automatic migration on first command. No manual `bd migrate` step required. The auto-migration shim detects the SQLite backend, runs the migration via `sqlite3 CLI`, and transitions to Dolt seamlessly.

## SSH Remotes & Dual-Surface Management

Dolt remote management now works over SSH with automatic fallback. When SQL-based push/pull fails (common with SSH remotes), Beads falls back to CLI-based operations. The `bd dolt remote add/list/remove` commands provide first-class remote management.

Auto-push to Dolt remotes runs with a 5-minute debounce — every write eventually syncs without manual intervention.

## Hook Migration System

A new hook census system detects outdated git hooks and plans migrations. `bd doctor` now reports hook health, and `bd init` auto-updates stale hooks. Section markers (BEGIN/END BEADS INTEGRATION) make hook updates safe even when users have custom hooks.

`hk` (hk.jdx.dev) joins the supported git hook managers alongside husky, lefthook, and pre-commit.

## Backup & Export

New `bd backup init/sync/restore` commands provide Dolt-native backup workflows. JSONL export (`bd export`) creates portable snapshots. Auto-backup activates when a git remote is configured — backups happen automatically on every Dolt commit.

## Lifecycle Commands

`bd gc`, `bd compact`, and `bd flatten` give standalone users direct control over their Beads data lifecycle without needing to understand Dolt internals.

## Agent Workflow Improvements

- **`bd doctor --agent`** — structured diagnostics mode for AI agents
- **PreToolUse hook** — blocks interactive prompts (cp/mv/rm -i) that hang agents
- **Config-driven metadata schema** — enforce metadata fields on creation
- **Label inheritance** — child issues automatically inherit parent labels
- **Auto-close molecule root** — when all steps complete, the root closes
- **CLI aliases** — `--comment` for `bd close`, `--yes/-y` for `bd mol burn`

## Testing Infrastructure

Behind the scenes, the test suite got a major overhaul:

- **Branch-per-test isolation** — tests run in isolated Dolt branches (doctor tests: 44s to 12s)
- **Test parallelization** — storage tests 3.5x faster, protocol tests 3x faster
- **Testcontainers** — test server uses containers instead of binary spawning
- **Production isolation** — tests no longer touch the production Dolt server

## Community Contributions

This release includes contributions from 12+ community members, including Windows compatibility fixes, Jira V2 API support, Linear Project sync, schema evolution resilience, and numerous doctor improvements.

## Upgrade Notes

- **Nix users**: `vendorHash` needs updating (`go.mod` dependencies changed)
- **Hook users**: Run `bd init` to update hooks to v0.57.0 section markers
- **SQLite users**: Migration is automatic on first `bd` command
