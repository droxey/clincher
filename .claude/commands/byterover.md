---
name: byterover
version: 1.0.0
description: |
  Query and curate project knowledge using ByteRover's persistent context tree.
  Use before starting work to recall patterns, decisions, and architectural rules.
  Use after completing work to store new insights for future sessions.
  Saves tokens by avoiding redundant file reads across sessions.
  Do not use for ephemeral data, secrets, or user-specific preferences.
  Do not use as a replacement for git commit messages or changelogs.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# ByteRover: Project Knowledge Management

Query and curate persistent project knowledge stored in `.brv/context-tree/`.
ByteRover saves tokens by giving agents structured memory — query before work,
curate after.

## Procedure

1. **Before any implementation task**, run `brv query` with a question about the
   relevant area:
   ```bash
   brv query "How is authentication implemented?"
   brv query "What are the deployment patterns for this project?"
   ```

2. **Read and apply** the returned context. ByteRover synthesizes answers from
   the local knowledge base — no need to re-read source files that have already
   been curated.

3. **After completing work**, curate new patterns and decisions:
   ```bash
   brv curate "Auth now uses JWT with 24h expiry. Tokens stored in httpOnly cookies."
   ```

4. **Include source files** when curating implementation details (max 5 files):
   ```bash
   brv curate "Refactored API middleware to use chain pattern" -f src/middleware/index.ts -f src/middleware/auth.ts
   ```

5. **Never** pass file contents via stdin or command substitution. Use the `-f`
   flag to let ByteRover read files directly — this avoids double-reads that
   waste tokens.

## Commands Reference

| Command | Purpose |
|---------|---------|
| `brv query "<question>"` | Retrieve relevant context from knowledge base |
| `brv curate "<insight>"` | Save new knowledge to context tree |
| `brv curate "<insight>" -f <path>` | Save knowledge with source file context |
| `brv curate view` | View curation history |
| `brv status` | Check auth, project, and provider state |
| `brv providers list` | List available LLM providers |
| `brv providers connect <name>` | Connect an LLM provider |

## When to Query

- Starting a new task or feature
- Before modifying unfamiliar code
- When you need to recall a past decision or trade-off
- Before proposing an architecture change

## When to Curate

- After implementing a significant change
- When discovering a non-obvious pattern or constraint
- After resolving a tricky bug (capture root cause and fix)
- When making an architectural decision with trade-offs

## Error Handling

- **"No knowledge found"**: Expected for new projects — curate initial context first.
- **Provider errors**: Run `brv status` to check provider connection.
- **File limit exceeded**: Max 5 files per curate command — split into multiple calls.

## Token Savings Verification

To verify ByteRover is saving tokens, compare two sessions:

1. **Without ByteRover**: Note how many files the agent reads to understand context.
2. **With ByteRover**: Run `brv query` first — the agent should skip reading files
   whose patterns are already curated, reducing token usage by 30-60% for
   context-heavy tasks.

Run `brv curate view` to see the knowledge base grow over time.
