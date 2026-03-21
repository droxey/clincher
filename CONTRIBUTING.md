# Contributing to Clincher

Thank you for your interest in contributing to clincher! This project welcomes contributions of all sizes.

## Ways to Contribute

### Add or Improve an Ansible Role

Each role lives in `roles/` and follows a consistent structure. To add a new role:

1. Create a new directory under `roles/` with `tasks/main.yml`
2. Add a Molecule test scenario under `roles/<name>/molecule/default/`
3. Wire it into `playbook.yml` with appropriate tags
4. Run `make check` to validate

### Improve a Prompt or Skill

Reusable agent-agnostic prompts live in `prompts/`. Claude Code slash commands live in `.claude/commands/`. Follow the [skill authoring guide](CLAUDE.md#skill--prompt-authoring) for structure and conventions.

### Report a Security Issue

**Do not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Fix a Bug or Improve Documentation

1. Fork the repository
2. Create a feature branch (`git checkout -b fix/description`)
3. Make your changes
4. Run `make check` to validate
5. Open a pull request

## Development Setup

```bash
# Clone and install dependencies
git clone https://github.com/droxey/clincher.git && cd clincher
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml

# Run the full CI suite locally
make check
```

## Commit Conventions

Use conventional commit prefixes with imperative mood, under 72 characters:

```
feat: add new monitoring role for Uptime Kuma
fix: resolve Redis password leak in docker-compose template
security: restrict egress whitelist to LLM provider domains only
docs: clarify Step 5 sandbox hardening instructions
```

## Code Standards

- **YAML**: Must pass `yamllint` and `ansible-lint` (production profile)
- **Shell scripts**: Use `set -euo pipefail`, `flock` for mutual exclusion, file-based secrets
- **Jinja2 templates**: Include Molecule test coverage for all conditional paths
- **Secrets**: Never hardcode IPs, passwords, or API keys — use placeholders (`<SERVER_IP>`, `<ADMIN_IP>`)

## Questions?

Open a [discussion](https://github.com/droxey/clincher/discussions) or file an [issue](https://github.com/droxey/clincher/issues).
