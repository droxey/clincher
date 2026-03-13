---
name: byterover
description: |
  Query and curate project knowledge using ByteRover's persistent context tree.
  Use before starting work to recall patterns and decisions. Use after completing
  work to store new insights. Saves tokens by avoiding redundant file reads.
  Do not use for ephemeral data, secrets, or user-specific preferences.
---

# ByteRover: Project Knowledge Management

Query and curate persistent project knowledge stored in `.brv/context-tree/`.

## Procedure

1. **Before implementation**, query the knowledge base for existing patterns:
   ```bash
   brv query "How is <relevant area> implemented?"
   ```

2. **Apply returned context** directly. Skip re-reading source files whose
   patterns are already curated.

3. **After completing work**, curate new insights:
   ```bash
   brv curate "<concise description of what changed and why>"
   ```

4. **Include source files** when curating (max 5 per command):
   ```bash
   brv curate "<insight>" -f <path1> -f <path2>
   ```

5. Use `-f` flags instead of piping file contents — avoids token-wasting
   double-reads.

## Commands

| Command | Purpose |
|---------|---------|
| `brv query "<question>"` | Retrieve context from knowledge base |
| `brv curate "<insight>"` | Save knowledge to context tree |
| `brv curate "<insight>" -f <path>` | Save with source file context |
| `brv curate view` | View curation history |
| `brv status` | Check project and provider state |

## When to Query

- Starting a new task or entering unfamiliar code
- Before proposing architecture changes
- When recalling past decisions or trade-offs

## When to Curate

- After implementing significant changes
- After discovering non-obvious patterns or constraints
- After resolving tricky bugs (capture root cause and fix)
- After making architectural decisions with trade-offs
