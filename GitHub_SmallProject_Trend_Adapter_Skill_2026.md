# GitHub 2026 Small-Project Trend Adapter Skill

> **Stack**: OpenClaw + Ansible (infrastructure / deployment guide)
> **Generated**: 2026-03-07 — based on Dec 2025–Mar 2026 trending small projects

---

## Last-3-Months Star Drivers (small-project summary)

Top trending small focused projects (<10k stars) in the AI-agent-deployment and DevOps tooling space from Dec 2025–Mar 2026:

| Repo | Stars | Stack | Why it exploded |
|------|-------|-------|-----------------|
| [skillshare](https://github.com/runkids/skillshare) | 776 | Go CLI | One-command skill sync across all AI CLIs; hero GIF, single binary, zero deps |
| [lobster](https://github.com/openclaw/lobster) | 748 | TypeScript | OpenClaw-native workflow shell; composable pipelines, typed, local-first |
| [pocketpaw](https://github.com/pocketpaw/pocketpaw) | 566 | Python | Self-hosted AI agent in 30 seconds; desktop installer, 7-layer security, multi-channel |
| [opencrabs](https://github.com/adolfousier/opencrabs) | 504 | Rust TUI | Single binary self-hosted AI agent; Ratatui terminal UI, zero config |
| [weft](https://github.com/jonesphillip/weft) | 483 | TypeScript | AI agents do your tasks; self-host on Cloudflare, minimal surface |
| [GoGogot](https://github.com/aspasskiy/GoGogot) | 388 | Go | Lightweight OpenClaw alternative; single binary, Docker Compose, minimal deps |
| [openclaw-dashboard](https://github.com/tugcantopaloglu/openclaw-dashboard) | 277 | Node.js/HTML | Real-time OpenClaw monitoring; TOTP MFA, cost tracking, Raspberry Pi ready |
| [sandboxed.sh](https://github.com/Th0rgal/sandboxed.sh) | 276 | Rust | AI agent orchestrator; isolated Linux workspaces, git-backed config, ~5 min setup |
| [ZeroClaw-Android](https://github.com/Natfii/ZeroClaw-Android) | 226 | Kotlin/Rust | Run AI agents 24/7 on Android; 25+ providers, encrypted storage, Material You |
| [gru](https://github.com/zscole/gru) | 213 | Python | AI agent orchestration via Telegram/Discord/Slack; single-purpose, minimal surface |

### Patterns driving star velocity

1. **One painful problem, solved perfectly** — each repo does exactly one thing
2. **One-command install** — `curl | sh`, `pip install x && x`, `brew install x`
3. **Hero visual in first 3 seconds** — GIF/video/screenshot above the fold
4. **Single binary or single compose file** — zero runtime deps where possible
5. **Security as a feature** — audit commands, isolation, encrypted storage sell trust
6. **AI-agent ecosystem hooks** — OpenClaw/Claude Code/Codex compatibility is a multiplier
7. **Flat repo structure** — <15 top-level items, no deep nesting
8. **Copy-paste quick start** — 3 commands max from zero to working
9. **Architecture diagrams** — ASCII or image showing data flow at a glance
10. **Star History chart** — social proof embedded in README footer

---

## Tech Stack Detector (one-shot classification prompt)

```
Classify this repository:

Primary language(s): YAML + Jinja2 (Ansible) + Markdown (documentation)
Framework: Ansible (roles, playbook, molecule tests, Galaxy collections)
Runtime: Docker Compose (target deployment)
Category: Infrastructure-as-Code / Deployment Guide / Security Hardening
Platform: OpenClaw AI agent platform
Deployment target: Single Ubuntu 24.04 VPS (KVM)
```

**Classification**: `Ansible + Docker Compose deployment guide for AI agent infrastructure`

---

## Universal Transformation Checklist (12 high-impact steps)

- [ ] **1. Hero visual** — Add architecture diagram or terminal recording (asciinema/GIF) showing `ansible-playbook playbook.yml` completing a full deploy in one shot
- [ ] **2. One-liner install** — Add a single `curl | sh` or `ansible-pull` command that bootstraps the entire deployment from zero
- [ ] **3. Problem statement** — Open README with the painful problem: "Deploying a hardened AI agent on a VPS takes hours of manual config. This does it in one command."
- [ ] **4. Slim badge row** — Add 4–5 badges max: CI status, Ansible version, license, OpenClaw version, last commit
- [ ] **5. Quick start above fold** — Move the 3-command quick start (`git clone`, `cp vault`, `ansible-playbook`) above the table of contents
- [ ] **6. Flatten structure** — Keep top-level items under 15; consolidate prompt files into a `prompts/` directory
- [ ] **7. Star History chart** — Add Star History embed in README footer for social proof
- [ ] **8. Security audit one-liner** — Surface the `openclaw security audit --deep` command prominently as a trust signal
- [ ] **9. Minimal badges** — Replace wall-of-text description with badges + 1-sentence pitch
- [ ] **10. Contributing fast-path** — Add `make lint` or equivalent one-liner for contributors
- [ ] **11. Topics/tags** — Set GitHub repo topics: `openclaw`, `ansible`, `docker-compose`, `self-hosted`, `security-hardening`, `vps-deployment`, `ai-agent`
- [ ] **12. Social links** — Add community link (Discord/Telegram) in README header for discoverability

---

## Tech-Specific Blueprints

### Ansible + Docker Compose Deployment Guides

**What works in 2026 for this niche:**

| Pattern | Implementation |
|---------|---------------|
| One-command deploy | `ansible-pull -U https://github.com/USER/REPO.git playbook.yml` or wrapper script |
| Idempotent re-runs | Already handled by Ansible — surface this as a feature |
| Verify after deploy | `make verify` → runs molecule + `openclaw security audit --deep` |
| Vars file as config | Single `group_vars/all/vars.yml` — document every variable with comments |
| Secret handling | `ansible-vault encrypt group_vars/all/vault.yml` — show the workflow |
| Role-per-concern | Already structured — mention this in README as a feature |

**README pattern for Ansible projects (from trending repos):**

```markdown
# Project Name

> One sentence: what painful problem this solves

[![CI](badge)][ci] [![Ansible](badge)][ansible] [![License](badge)][license]

[GIF or architecture diagram here]

## Quick Start

\```bash
git clone https://github.com/USER/REPO.git && cd REPO
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
# Edit vault.yml with your secrets
ansible-playbook playbook.yml
\```

## What You Get

[Architecture diagram + service table]

## Configuration

[Link to vars.yml with inline docs]

## Security

[One-liner audit command + trust signals]
```

### OpenClaw Ecosystem Projects

**What makes OpenClaw-adjacent repos trend:**

1. **Compatible with the ecosystem** — mention OpenClaw version compatibility
2. **Solve operator pain** — deployment, monitoring, backup, security
3. **One Compose file** — the entire stack in one `docker-compose.yml`
4. **Hardening as a headline feature** — the security angle drives trust and shares

---

## Golden README Template

```markdown
<p align="center">
  <img src="docs/architecture.png" alt="PROJECT_NAME" width="600">
</p>

<h1 align="center">PROJECT_NAME</h1>

<p align="center">
  <strong>One sentence describing the painful problem you solve.</strong><br>
  One command. Hardened by default. Production-ready.
</p>

<p align="center">
  <a href="LINK"><img src="https://img.shields.io/github/actions/workflow/status/USER/REPO/ci.yml?label=CI" alt="CI"></a>
  <a href="LINK"><img src="https://img.shields.io/badge/Ansible-2.17+-red?logo=ansible" alt="Ansible"></a>
  <a href="LINK"><img src="https://img.shields.io/badge/OpenClaw-2026.2-blue" alt="OpenClaw"></a>
  <a href="LINK"><img src="https://img.shields.io/github/license/USER/REPO" alt="License"></a>
  <a href="LINK"><img src="https://img.shields.io/github/stars/USER/REPO?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#security">Security</a> •
  <a href="#docs">Docs</a>
</p>

---

## The Problem

Deploying [TOOL] securely on a VPS means hours of manual config:
firewall rules, egress proxies, socket isolation, sandbox hardening, credential rotation.
Miss one step and your agent has root-equivalent access to the internet.

**This repo does it in one command.**

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/USER/REPO.git && cd REPO

# 2. Configure secrets
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
$EDITOR group_vars/all/vault.yml
ansible-vault encrypt group_vars/all/vault.yml

# 3. Deploy
ansible-playbook playbook.yml -i inventory/hosts.yml --ask-vault-pass
```

**That's it.** Your hardened AI agent is running.

---

## What You Get

[Architecture diagram — ASCII or image]

| Service | Purpose |
|---------|---------|
| ... | ... |

---

## Security

```bash
# Run a deep security audit
docker exec $(docker ps -q -f "name=openclaw") openclaw security audit --deep
```

- Network isolation (3 bridge networks, internal-only default)
- Egress whitelist (only LLM API domains)
- Socket proxy (read-only, EXEC-only)
- Sandbox hardening (capDrop=ALL, network=none)
- 13 dangerous tools blocked at gateway + agent level
- File-based secret passing (never CLI args)
- UFW + fail2ban + admin IP whitelist

---

## Verify

```bash
make verify  # or: molecule test && ansible-playbook playbook.yml --check
```

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=USER/REPO&type=Date)](https://star-history.com/#USER/REPO)

---

## License

MIT
```

---

## Modern Repo Structure (flat & minimal)

**Target: <15 top-level items**

```
repo/
├── README.md                    # Hero README (Golden Template above)
├── LICENSE                      # MIT
├── CLAUDE.md                    # AI assistant context
├── Makefile                     # lint, test, deploy, verify one-liners
├── ansible.cfg                  # Ansible config
├── playbook.yml                 # Main playbook
├── requirements.yml             # Galaxy collections
├── requirements.txt             # Python deps (ansible, molecule, etc.)
├── inventory/
│   └── hosts.yml
├── group_vars/
│   └── all/
│       ├── vars.yml
│       └── vault.yml.example
├── roles/                       # One role per concern
│   ├── base/
│   ├── openclaw-config/
│   ├── openclaw-deploy/
│   ├── openclaw-harden/
│   ├── openclaw-integrate/
│   ├── reverse-proxy/
│   ├── verify/
│   ├── maintenance/
│   └── monitoring/
├── molecule/                    # Tests
├── docs/                        # Architecture diagrams, screenshots
│   ├── architecture.png
│   └── terminal-demo.gif
├── prompts/                     # AI prompt templates (moved from root)
│   ├── code-review-ansible.md
│   ├── deployment-guide.md
│   └── virality-skill.md
└── .github/
    ├── workflows/ci.yml
    ├── ISSUE_TEMPLATE/
    ├── PULL_REQUEST_TEMPLATE.md
    └── dependabot.yml
```

**Key changes from current structure:**
- Add `Makefile` for one-liner DX (`make deploy`, `make lint`, `make test`, `make verify`)
- Add `docs/` for visual assets (architecture diagram, terminal recording)
- Move `PROMPT_*.md` files into `prompts/` directory (reduce root clutter)
- Add `LICENSE` file at root
- Add `.github/ISSUE_TEMPLATE/` and `PULL_REQUEST_TEMPLATE.md`

---

## .github/ Power Pack

### CI Workflow (lightweight)

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt
      - run: yamllint .
      - run: ansible-lint
      - run: ansible-playbook playbook.yml --syntax-check

  molecule:
    needs: lint
    runs-on: ubuntu-latest
    strategy:
      matrix:
        scenario: [default, openclaw-config, maintenance]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt
      - run: molecule test -s ${{ matrix.scenario }}
```

### Issue Templates

```yaml
# .github/ISSUE_TEMPLATE/bug_report.yml
name: Bug Report
description: Report a deployment or configuration issue
labels: [bug]
body:
  - type: dropdown
    id: step
    attributes:
      label: Which deployment step?
      options:
        - "Step 1: Prerequisites"
        - "Step 2: Firewall"
        - "Step 3: Configuration"
        - "Step 4: Deploy"
        - "Step 5: Hardening"
        - "Step 6-8: Integration"
        - "Step 9: Reverse Proxy"
        - "Step 10: Verification"
        - "Step 11-14: Maintenance/HA"
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual behavior
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Relevant logs
      render: shell
```

### Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
```

### PR Template

```markdown
<!-- .github/PULL_REQUEST_TEMPLATE.md -->
## What

<!-- One sentence: what does this PR do? -->

## Why

<!-- What problem does it solve? -->

## Testing

- [ ] `yamllint .` passes
- [ ] `ansible-lint` passes
- [ ] `ansible-playbook playbook.yml --syntax-check` passes
- [ ] `molecule test` passes (if role changed)

## Deployment step affected

<!-- Which of the 14 steps does this change? -->
```

---

## Virality Playbook

### 1. Solve one painful problem perfectly

**The problem**: Deploying a hardened AI agent on a VPS is a multi-hour, error-prone manual process with dozens of security decisions to get right.

**The solution**: One Ansible playbook that handles everything — firewall, egress proxy, socket isolation, sandbox hardening, credential rotation, monitoring, backups — idempotently.

**Positioning**: "The hardened OpenClaw deployment that security engineers would approve."

### 2. Visual hero README

- [ ] Record a 30-second terminal GIF with [asciinema](https://asciinema.org/) + [agg](https://github.com/asciinema/agg) showing `ansible-playbook playbook.yml` completing successfully
- [ ] Create a clean architecture diagram (use [Excalidraw](https://excalidraw.com/) or [mermaid](https://mermaid.js.org/)) showing the 3-network topology
- [ ] Place the visual above the fold in README, before any text

### 3. One-command install

Add to README:

```bash
# One-command deploy (requires Ansible on control node)
ansible-pull -U https://github.com/YOUR_USERNAME/clincher.git playbook.yml \
  -i inventory/hosts.yml --ask-vault-pass
```

Or a bootstrap script:

```bash
curl -fsSL https://raw.githubusercontent.com/USER/clincher/main/bootstrap.sh | bash
```

### 4. AI polish

- [x] CLAUDE.md exists with full project context (already done)
- [ ] Add `.github/copilot-instructions.md` for GitHub Copilot users
- [ ] Ensure every role has a descriptive `meta/main.yml` with Galaxy metadata

### 5. Star-growth levers

| Lever | Action |
|-------|--------|
| **Awesome list** | Submit to [awesome-openclaw](https://github.com/vincentkoc/awesome-openclaw) |
| **Reddit/HN** | Post to r/selfhosted, r/ansible, r/homelab with "Show HN" style |
| **OpenClaw community** | Share in OpenClaw Discord/forums as reference deployment |
| **Cross-link** | Add to related projects: pocketpaw, sandboxed.sh, openclaw-dashboard |
| **Blog post** | "How I hardened my AI agent VPS in one command" walkthrough |
| **Twitter/X thread** | 5-tweet thread: problem → architecture → one-command → security audit → link |
| **GitHub Topics** | Tag repo: `openclaw`, `ansible`, `self-hosted`, `docker-compose`, `security-hardening` |

### 6. DX speed

Add a `Makefile` for instant contributor onboarding:

```makefile
.PHONY: lint test deploy verify

lint:                          ## Run all linters
	yamllint . && ansible-lint

test:                          ## Run molecule tests
	molecule test

deploy:                        ## Deploy to target server
	ansible-playbook playbook.yml -i inventory/hosts.yml --ask-vault-pass

verify:                        ## Verify deployment
	ansible-playbook playbook.yml -i inventory/hosts.yml --tags verify

check: lint test               ## Run lint + test (CI equivalent)

help:                          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
```

---

## Agent Execution Protocol (step-by-step refactor script)

When an agent loads this skill, execute these steps in order:

### Phase 1: Assess (read-only)

```
1. Read README.md — note length, structure, presence of visuals
2. Read repo root — count top-level items
3. Check for: Makefile, LICENSE, .github/ISSUE_TEMPLATE/, architecture diagram
4. Check GitHub topics on the repo
5. Run existing linters: yamllint . && ansible-lint && ansible-playbook playbook.yml --syntax-check
```

### Phase 2: Quick wins (5 minutes, high impact)

```
6. Add badge row to README top (CI, Ansible version, OpenClaw version, license, stars)
7. Add Star History chart to README bottom
8. Create Makefile with lint/test/deploy/verify targets
9. Set GitHub repo topics if not already set
10. Add one-liner quick start section above table of contents
```

### Phase 3: README restructure (15 minutes)

```
11. Add hero section: centered title + 1-sentence pitch + badges + nav links
12. Add "The Problem" section (2–3 sentences, pain-focused)
13. Add "Quick Start" section (3 commands max)
14. Add "What You Get" section with architecture diagram + service table
15. Add "Security" section with audit one-liner + bullet list
16. Move detailed 14-step guide into collapsible <details> or separate docs/
```

### Phase 4: Repo hygiene (10 minutes)

```
17. Add LICENSE file (MIT) if missing
18. Move PROMPT_*.md files to prompts/ directory
19. Add .github/ISSUE_TEMPLATE/bug_report.yml
20. Add .github/PULL_REQUEST_TEMPLATE.md
21. Add .github/dependabot.yml (Actions + pip)
22. Verify .gitignore covers: *.retry, .molecule/, __pycache__/, *.pyc
```

### Phase 5: Visuals (when tools available)

```
23. Record terminal demo GIF (asciinema + agg) of successful deploy
24. Create architecture diagram (Excalidraw/mermaid) of 3-network topology
25. Place hero visual above fold in README
```

### Phase 6: Distribution

```
26. Submit PR to awesome-openclaw
27. Set GitHub repo topics
28. Prepare r/selfhosted post draft
```

---

## Validation Rubric (1–10 small-project trend score)

| # | Criterion | Weight | Score (1–10) |
|---|-----------|--------|:------------:|
| 1 | **Hero visual above fold** (GIF/screenshot/diagram) | 15% | __ |
| 2 | **One-command install/deploy** (≤3 steps from zero to working) | 15% | __ |
| 3 | **Solves one painful problem perfectly** (clear positioning) | 15% | __ |
| 4 | **Minimal README** (scannable in 30 seconds, no wall of text) | 10% | __ |
| 5 | **Badge row** (CI, version, license — 5 max) | 5% | __ |
| 6 | **Flat repo structure** (<15 top-level items) | 5% | __ |
| 7 | **Security trust signals** (audit command, hardening list) | 10% | __ |
| 8 | **DX shortcuts** (Makefile/scripts, contributing guide) | 5% | __ |
| 9 | **Star History + social proof** (chart, contributor list) | 5% | __ |
| 10 | **AI ecosystem compatibility** (CLAUDE.md, copilot instructions) | 5% | __ |
| 11 | **GitHub Power Pack** (issue templates, PR template, dependabot) | 5% | __ |
| 12 | **Community/distribution plan** (awesome list, topics, cross-links) | 5% | __ |

**Scoring guide:**
- **9–10**: Ready to trend. Ship it.
- **7–8**: Strong foundation. Missing 1–2 visual/distribution elements.
- **5–6**: Functional but invisible. Needs README overhaul + visuals.
- **3–4**: Good code, poor packaging. Full transformation needed.
- **1–2**: Needs fundamental restructuring.

### Before/After Checklist (for this repo)

| Item | Before | After |
|------|:------:|:-----:|
| Hero visual above fold | ❌ | ☐ |
| One-command deploy | ❌ | ☐ |
| Problem statement in first 3 lines | ❌ | ☐ |
| Badge row | ❌ | ☐ |
| Quick start above ToC | ❌ | ☐ |
| Makefile | ❌ | ☐ |
| Star History chart | ❌ | ☐ |
| Issue templates | ❌ | ☐ |
| PR template | ❌ | ☐ |
| Dependabot config | ❌ | ☐ |
| GitHub topics set | ❌ | ☐ |
| Architecture diagram (clean) | Partial (ASCII in README) | ☐ |
| prompts/ directory | ❌ (files at root) | ☐ |
| LICENSE file at root | ❌ | ☐ |
| Security audit prominent | Partial (buried in Step 10) | ☐ |
| CLAUDE.md | ✅ | ✅ |
| Molecule tests | ✅ | ✅ |
| CI workflow | ✅ | ✅ |
| Ansible-lint config | ✅ | ✅ |

**Current estimated score (baseline, before applying this skill): 4/10** — solid infrastructure code and security model, but poor discoverability packaging. The 14-step guide is thorough but buries the value proposition. Applying this skill should bring the score to 8+/10.
