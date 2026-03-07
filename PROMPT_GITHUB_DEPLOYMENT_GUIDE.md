You are a Principal DevOps Engineer and GitHub expert with up-to-date knowledge as of March 2026. You specialize in production-grade deployments from GitHub repositories using modern GitHub-native tools.

A developer has a project in GitHub (Ansible playbook). Provide a complete 2026 best-practices deployment guide covering all sections below.

---

## Progress Tracker

### Phase 1 — Critical Gaps

- [x] Define `_syntax.yml` reusable workflow (broken reference in `ci.yml`)
- [x] Complete blue-green Caddy upstream switch (was a placeholder comment)
- [x] Add rollback task block

### Phase 2 — Missing Artifacts

- [x] Add `renovate.json` for Galaxy collection version bumps
- [x] Add standalone `ee-build.yml` workflow with proper triggers
- [x] Add `notify-deploy-failure.yml` using `workflow_run` event
- [x] Add OpenTelemetry callback configuration

### Phase 3 — Thin Sections

- [x] Add GitHub Environments step-by-step setup (required reviewers, branch rules)

### Phase 4 — Lint Cleanup

- [x] Fix MD040: add language specifiers to all fenced code blocks
- [x] Fix MD060: add spaces around pipe separators in all table rows

---

# GitHub Deployment Guide — Ansible Playbook (2026)

## Executive Summary: The 2026 GitHub Deployment Landscape

By March 2026 the GitHub ecosystem has converged on five non-negotiable defaults for every production Ansible project:

1. **OIDC everywhere** — long-lived secrets in repository settings are gone. Every cloud action authenticates with short-lived OIDC tokens.
2. **Reusable workflows + composite actions** — `.github/workflows/` is itself a library. `ci.yml` calls `_lint.yml`, `_molecule.yml`, and `_deploy.yml` rather than duplicating steps.
3. **Environments with required reviewers** — `staging` auto-deploys; `production` gates on human approval. GitHub Environments replaced every home-grown approval gate.
4. **Dependency review + CodeQL in the merge queue** — nothing reaches `main` without a passing security scan.
5. **Molecule as the unit test for roles** — `molecule test` is the Ansible equivalent of `pytest`. If it doesn't have a Molecule scenario, it isn't production-ready.

---

## Step-by-Step Implementation Guide

### 1. Repository Setup & Branching Strategy

**Trunk-based development with short-lived feature branches:**

```text
main          ← protected, requires PR + passing CI + 1 review
├── feature/  ← merged in < 2 days; triggers CI on push
├── fix/      ← hotfix; fast-path to main
└── release/  ← optional; tag-triggered deploys to production
```

**Branch protection rules for `main` (Settings → Branches):**

- Require a pull request before merging (1 required reviewer)
- Require status checks: `ci / lint`, `ci / molecule`, `security / codeql`
- Require branches to be up to date before merging
- Restrict who can push to matching branches
- Do not allow bypassing the above settings (including admins)

**Tag convention for releases:**

```text
v2026.3.7          ← CalVer (YYYY.M.D) matches OpenClaw's own tagging scheme
v2026.3.7-rc.1     ← release candidate; deploys to staging only
```

---

### 2. CI/CD with GitHub Actions

**Workflow file layout:**

```text
.github/
├── workflows/
│   ├── ci.yml                    ← orchestrator; calls reusable workflows
│   ├── deploy.yml                ← environment-gated deployment
│   ├── ee-build.yml              ← builds Ansible Execution Environment
│   ├── notify-deploy-failure.yml ← workflow_run failure alerts
│   ├── drift.yml                 ← cron drift detection
│   ├── security.yml              ← CodeQL + dependency review
│   ├── _lint.yml                 ← reusable: ansible-lint + yamllint
│   ├── _molecule.yml             ← reusable: Molecule test matrix
│   └── _syntax.yml               ← reusable: ansible-playbook --syntax-check
└── dependabot.yml                ← Actions SHA bumps + pip updates
```

**`ci.yml` — Main orchestrator:**

```yaml
# .github/workflows/ci.yml
# Orchestrates lint → syntax → molecule on every PR and push to main.
# All jobs call reusable workflows to keep this file < 30 lines.

name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Cancel in-flight runs for the same branch when a new push arrives.
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    uses: ./.github/workflows/_lint.yml
    secrets: inherit

  syntax:
    uses: ./.github/workflows/_syntax.yml
    secrets: inherit

  molecule:
    needs: [lint, syntax]
    uses: ./.github/workflows/_molecule.yml
    with:
      scenario-matrix: '["default", "hardened"]'
    secrets: inherit
```

**`_lint.yml` — Reusable lint workflow:**

```yaml
# .github/workflows/_lint.yml
# Reusable workflow: ansible-lint (production profile) + yamllint.
# Pinned to SHA for supply-chain safety.

name: Lint

on:
  workflow_call:

jobs:
  ansible-lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install lint tools
        run: pip install ansible-lint==25.4.0 yamllint==1.35.1

      - name: Run yamllint
        run: yamllint -c .yamllint .

      - name: Run ansible-lint (production profile)
        run: ansible-lint --profile production

      - name: Run ansible-lint (SARIF output for Security tab)
        run: ansible-lint --profile production -f sarif -o ansible-lint.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@ce28f5bb42b7a9f2c824e633a3f6ee835bab6858  # v3.28.9
        with:
          sarif_file: ansible-lint.sarif
```

**`_syntax.yml` — Reusable syntax-check workflow:**

```yaml
# .github/workflows/_syntax.yml
# Reusable workflow: ansible-playbook --syntax-check against the staging
# inventory. Catches template errors and undefined variables before Molecule
# runs, which is significantly faster to fail.

name: Syntax Check

on:
  workflow_call:

jobs:
  syntax:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Cache Ansible collections
        uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684  # v4.2.1
        with:
          path: ~/.ansible/collections
          key: ansible-collections-${{ hashFiles('requirements.yml') }}

      - name: Install Ansible
        run: pip install ansible-core==2.20.0

      - name: Install collections
        run: ansible-galaxy collection install -r requirements.yml

      - name: Syntax check
        run: |
          ansible-playbook playbook.yml \
            --syntax-check \
            -i inventory/staging/hosts.yml
```

**`_molecule.yml` — Reusable Molecule test workflow:**

```yaml
# .github/workflows/_molecule.yml
# Reusable workflow: runs Molecule scenarios in a matrix.
# Caches pip install and Galaxy collections between runs.

name: Molecule

on:
  workflow_call:
    inputs:
      scenario-matrix:
        description: "JSON array of Molecule scenario names"
        type: string
        default: '["default"]'

jobs:
  molecule:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        scenario: ${{ fromJSON(inputs.scenario-matrix) }}

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Cache Ansible collections
        uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684  # v4.2.1
        with:
          path: ~/.ansible/collections
          key: ansible-collections-${{ hashFiles('requirements.yml') }}

      - name: Install Molecule + dependencies
        run: |
          pip install molecule==25.3.0 molecule-plugins[docker]==23.7.0 \
            ansible-core==2.20.0 ansible-lint==25.4.0

      - name: Install Ansible collections
        run: ansible-galaxy collection install -r requirements.yml

      - name: Run Molecule — ${{ matrix.scenario }}
        run: molecule test --scenario-name ${{ matrix.scenario }}
        env:
          PY_COLORS: "1"
          ANSIBLE_FORCE_COLOR: "1"
```

**`deploy.yml` — Environment-gated deployment:**

```yaml
# .github/workflows/deploy.yml
# Deploys playbook to staging (auto) then production (manual approval).
# Uses OIDC — no long-lived SSH keys or cloud credentials in secrets.
# Triggered by a version tag push (e.g. v2026.3.7).

name: Deploy

on:
  push:
    tags: ["v*"]
  workflow_dispatch:
    inputs:
      environment:
        description: "Target environment"
        required: true
        type: choice
        options: [staging, production]

jobs:
  deploy-staging:
    name: Deploy → Staging
    runs-on: ubuntu-24.04
    environment: staging
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Obtain SSH certificate (OIDC → Vault)
        uses: hashicorp/vault-action@d1720f055e0635fd932a1d2a48f87a666a57906c  # v3.1.0
        with:
          url: ${{ secrets.VAULT_ADDR }}
          method: jwt
          role: ansible-deploy-staging
          secrets: |
            ssh/sign/ansible public_key=@~/.ssh/id_ed25519.pub | SSH_CERT ;

      - name: Set up Python + Ansible
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install Ansible
        run: pip install ansible-core==2.20.0

      - name: Install collections
        run: ansible-galaxy collection install -r requirements.yml

      - name: Run playbook — staging
        run: |
          ansible-playbook playbook.yml \
            -i inventory/staging/hosts.yml \
            --vault-password-file <(echo "$VAULT_PASS") \
            --diff
        env:
          VAULT_PASS: ${{ secrets.ANSIBLE_VAULT_PASS }}
          ANSIBLE_HOST_KEY_CHECKING: "False"

      - name: Post-deploy health check
        run: |
          ansible -i inventory/staging/hosts.yml all \
            -m ansible.builtin.uri \
            -a "url=http://localhost:3000/health status_code=200" \
            --vault-password-file <(echo "$VAULT_PASS")
        env:
          VAULT_PASS: ${{ secrets.ANSIBLE_VAULT_PASS }}

  deploy-production:
    name: Deploy → Production
    needs: deploy-staging
    runs-on: ubuntu-24.04
    environment: production
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Obtain SSH certificate (OIDC → Vault)
        uses: hashicorp/vault-action@d1720f055e0635fd932a1d2a48f87a666a57906c  # v3.1.0
        with:
          url: ${{ secrets.VAULT_ADDR }}
          method: jwt
          role: ansible-deploy-production
          secrets: |
            ssh/sign/ansible public_key=@~/.ssh/id_ed25519.pub | SSH_CERT ;

      - name: Set up Python + Ansible
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install Ansible
        run: pip install ansible-core==2.20.0

      - name: Install collections
        run: ansible-galaxy collection install -r requirements.yml

      - name: Run playbook — production
        run: |
          ansible-playbook playbook.yml \
            -i inventory/production/hosts.yml \
            --vault-password-file <(echo "$VAULT_PASS") \
            --diff
        env:
          VAULT_PASS: ${{ secrets.ANSIBLE_VAULT_PASS }}
          ANSIBLE_HOST_KEY_CHECKING: "False"

      - name: Post-deploy health check
        run: |
          ansible -i inventory/production/hosts.yml all \
            -m ansible.builtin.uri \
            -a "url=http://localhost:3000/health status_code=200" \
            --vault-password-file <(echo "$VAULT_PASS")
        env:
          VAULT_PASS: ${{ secrets.ANSIBLE_VAULT_PASS }}

      - name: Notify Slack on deploy result
        if: always()
        uses: slackapi/slack-github-action@37ebaef184d7626c5f204ab8d3baff4262dd30f0  # v2.1.0
        with:
          payload: |
            {
              "text": "${{ job.status == 'success' && ':white_check_mark:' || ':x:' }} Production deploy *${{ github.ref_name }}* — ${{ job.status }}",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Repo:* ${{ github.repository }}\n*Tag:* ${{ github.ref_name }}\n*Actor:* ${{ github.actor }}\n*Status:* ${{ job.status }}\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View run>"
                }
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          SLACK_WEBHOOK_TYPE: INCOMING_WEBHOOK
```

---

### 3. Security & Compliance

**`security.yml` — CodeQL + dependency review:**

```yaml
# .github/workflows/security.yml
# Runs on PRs and a weekly schedule.
# CodeQL scans Python/YAML; dependency-review blocks vulnerable Galaxy
# collections and pip packages before they reach main.

name: Security

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  codeql:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Initialize CodeQL
        uses: github/codeql-action/init@ce28f5bb42b7a9f2c824e633a3f6ee835bab6858  # v3.28.9
        with:
          languages: python
          queries: security-and-quality

      - name: Perform CodeQL analysis
        uses: github/codeql-action/analyze@ce28f5bb42b7a9f2c824e633a3f6ee835bab6858  # v3.28.9

  dependency-review:
    runs-on: ubuntu-24.04
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Dependency review
        uses: actions/dependency-review-action@da24cf0b2a6a4e894a78a2c19e24e1e5ee1be6a7  # v4.6.0
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0
```

**`dependabot.yml` — Auto-update Actions + pip:**

```yaml
# .github/dependabot.yml
# Weekly PRs for GitHub Actions SHA bumps and pip (Ansible tools) updates.
# Galaxy collection bumps are handled by Renovate Bot (see renovate.json) —
# Dependabot does not natively support ansible-galaxy as of March 2026.

version: 2

updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: "chore(deps)"
    labels: ["dependencies", "github-actions"]

  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: "chore(deps)"
    labels: ["dependencies", "python"]
```

**OIDC trust policy (Vault HCL example):**

```hcl
# Vault: JWT auth role for GitHub Actions OIDC.
# Scope is locked to the exact repo and the "staging" environment.
# Production gets a separate role with a separate policy.

resource "vault_jwt_auth_backend_role" "ansible_deploy_staging" {
  backend        = vault_jwt_auth_backend.github.path
  role_name      = "ansible-deploy-staging"
  token_policies = ["ansible-staging-policy"]

  bound_claims = {
    repository = "droxey/clincher"
    environment = "staging"
    ref_type    = "tag"
  }

  user_claim = "actor"
  role_type  = "jwt"
  ttl        = "900"
}
```

**Least-privilege `GITHUB_TOKEN` permissions:**

```yaml
# Set at workflow level. Grant only what the job needs.
permissions:
  contents: read
  id-token: write
  pull-requests: write
```

**GitHub Environments setup — step by step:**

GitHub Environments enforce deployment gates and inject environment-scoped secrets. Set them up before the first deploy.

1. Go to **Settings → Environments → New environment**
2. Create `staging`:
   - **No required reviewers** — staging auto-deploys on every tag
   - **Deployment branch rule**: `v*` tags only
   - Add secrets: `ANSIBLE_VAULT_PASS`, `VAULT_ADDR`, `SLACK_WEBHOOK_URL`
3. Create `production`:
   - **Required reviewers**: add 1–2 named individuals (not teams — teams require GitHub Team plan)
   - **Wait timer**: optionally set 5 minutes to allow last-minute cancellation
   - **Deployment branch rule**: `v*` tags only (prevents `workflow_dispatch` from targeting production on arbitrary branches)
   - Add the same secrets as staging (separate values for each environment)
4. In `deploy.yml`, the `environment: production` key on the job causes GitHub to pause and request approval from the named reviewers before the job runs. The approval UI is at **Actions → [run] → Review deployments**.

---

### 4. Containerization & Orchestration

Ansible playbooks are not containerized applications — they run on a **controller node** and manage remote hosts over SSH. The right containerization story is the **Ansible Execution Environment (EE)**, not a generic Docker image.

**`execution-environment.yml`:**

```yaml
# execution-environment.yml
# Defines the container image used as the Ansible controller in CI and AWX/AAP.
# Build with: ansible-builder build -t ghcr.io/droxey/clincher-ee:2026.3.7

version: 3

images:
  base_image:
    name: ghcr.io/ansible/community-ee-minimal:2.20.0

dependencies:
  galaxy: requirements.yml
  python: requirements.txt
  system:
    - openssh-client
    - curl

options:
  package_manager_path: /usr/bin/microdnf
```

**`ee-build.yml` — Standalone EE build workflow:**

```yaml
# .github/workflows/ee-build.yml
# Builds and pushes the Ansible Execution Environment to GHCR.
# Triggers when execution-environment.yml, requirements.yml, or
# requirements.txt change on main. Also supports manual dispatch.

name: Build Execution Environment

on:
  push:
    branches: [main]
    paths:
      - execution-environment.yml
      - requirements.yml
      - requirements.txt
  workflow_dispatch:
    inputs:
      push:
        description: "Push image to GHCR after build"
        type: boolean
        default: true

concurrency:
  group: ee-build-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      packages: write
      contents: read

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Log in to GHCR
        uses: docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772  # v3.4.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install ansible-builder
        run: pip install ansible-builder==3.1.0

      - name: Compute image tags
        id: tags
        run: |
          SHORT_SHA="${GITHUB_SHA::7}"
          DATE=$(date -u +%Y.%-m.%-d)
          REGISTRY="ghcr.io/${{ github.repository_owner }}/clincher-ee"
          echo "date_tag=${REGISTRY}:${DATE}" >> "$GITHUB_OUTPUT"
          echo "sha_tag=${REGISTRY}:${SHORT_SHA}" >> "$GITHUB_OUTPUT"

      - name: Build EE
        run: |
          ansible-builder build \
            -t ${{ steps.tags.outputs.date_tag }} \
            --container-runtime docker \
            -v 3

      - name: Tag with short SHA
        run: |
          docker tag \
            ${{ steps.tags.outputs.date_tag }} \
            ${{ steps.tags.outputs.sha_tag }}

      - name: Push images
        if: github.event_name != 'workflow_dispatch' || inputs.push
        run: |
          docker push ${{ steps.tags.outputs.date_tag }}
          docker push ${{ steps.tags.outputs.sha_tag }}

      - name: Write job summary
        run: |
          echo "### EE Image Built" >> "$GITHUB_STEP_SUMMARY"
          echo "| Tag | Value |" >> "$GITHUB_STEP_SUMMARY"
          echo "| --- | --- |" >> "$GITHUB_STEP_SUMMARY"
          echo "| Date | \`${{ steps.tags.outputs.date_tag }}\` |" >> "$GITHUB_STEP_SUMMARY"
          echo "| SHA  | \`${{ steps.tags.outputs.sha_tag }}\` |"  >> "$GITHUB_STEP_SUMMARY"
```

**Registry options in 2026:**

| Registry | Best For | Notes |
| --- | --- | --- |
| GHCR (`ghcr.io`) | OSS projects, GitHub-native | Free for public; `GITHUB_TOKEN` auth |
| AWS ECR | AWS-deployed controllers | OIDC auth via `aws-actions/configure-aws-credentials` |
| Quay.io | Red Hat / AAP users | Native EE registry; robot accounts for CI |

---

### 5. Infrastructure as Code & GitOps

**Repository as the single source of truth:**

```text
.
├── inventory/
│   ├── staging/
│   │   └── hosts.yml     ← staging targets (IPs in vault, not plaintext)
│   └── production/
│       └── hosts.yml     ← production targets
├── group_vars/
│   └── all/
│       ├── vars.yml      ← non-secret config
│       └── vault.yml     ← ansible-vault encrypted; committed to repo
└── playbook.yml
```

**GitOps flow with Ansible:**

There is no Flux/ArgoCD equivalent for Ansible playbooks (those tools target Kubernetes manifests). The GitOps pattern for Ansible is:

1. **Push to `main`** → GitHub Actions runs `ansible-playbook` against staging
2. **Tag a release** → same workflow runs against production after approval
3. **Drift detection** — run playbook with `--check --diff` on a cron schedule; alert on non-zero exit

**`renovate.json` — Galaxy collection version bumps:**

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "ansible": {
    "enabled": true
  },
  "packageRules": [
    {
      "matchManagers": ["ansible-galaxy"],
      "automerge": false,
      "labels": ["dependencies", "ansible-galaxy"],
      "commitMessagePrefix": "chore(deps): "
    },
    {
      "matchManagers": ["github-actions"],
      "automerge": false,
      "pinDigests": true,
      "labels": ["dependencies", "github-actions"],
      "commitMessagePrefix": "chore(deps): "
    },
    {
      "matchManagers": ["pip_requirements"],
      "automerge": false,
      "labels": ["dependencies", "python"],
      "commitMessagePrefix": "chore(deps): "
    }
  ]
}
```

**Drift detection cron job:**

```yaml
# .github/workflows/drift.yml
name: Drift Detection

on:
  schedule:
    - cron: "0 */6 * * *"

jobs:
  check-drift:
    runs-on: ubuntu-24.04
    environment: production
    permissions:
      id-token: write
      contents: read
      issues: write

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python + Ansible
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install Ansible
        run: pip install ansible-core==2.20.0

      - name: Install collections
        run: ansible-galaxy collection install -r requirements.yml

      - name: Check for drift
        id: drift
        run: |
          set +e
          ansible-playbook playbook.yml \
            -i inventory/production/hosts.yml \
            --vault-password-file <(echo "$VAULT_PASS") \
            --check --diff 2>&1 | tee drift-report.txt
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"
        env:
          VAULT_PASS: ${{ secrets.ANSIBLE_VAULT_PASS }}

      - name: Open issue on drift
        if: steps.drift.outputs.exit_code != '0'
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea  # v7.0.1
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('drift-report.txt', 'utf8');
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `[Drift] Production drift detected ${new Date().toISOString()}`,
              body: `\`\`\`\n${report.slice(0, 60000)}\n\`\`\``,
              labels: ['drift', 'production']
            });
```

---

### 6. Deployment Strategies

Ansible playbooks managing a **single server** (as in this project) use a simplified deployment model — blue-green and canary apply at the **service level** (Docker containers) rather than the infrastructure level.

**Staging → Production promotion:**

```text
feature/* ──► PR to main ──► CI passes ──► merge to main
                                                │
                                          auto-deploy to staging
                                                │
                                     manual tag: git tag v2026.3.7
                                                │
                                          deploy.yml triggers
                                                │
                                    staging job runs (auto-approve)
                                                │
                                    production job waits for reviewer
                                                │
                                          reviewer approves in GitHub UI
                                                │
                                          production deploy runs
```

**Blue-green at the Docker layer (`roles/openclaw-deploy/tasks/blue-green.yml`):**

```yaml
- name: Pull new image
  community.docker.docker_image:
    name: "ghcr.io/openclaw/openclaw:{{ openclaw_version }}"
    source: pull
    force_source: true

- name: Start green container
  community.docker.docker_container:
    name: openclaw-green
    image: "ghcr.io/openclaw/openclaw:{{ openclaw_version }}"
    networks:
      - name: openclaw-net
      - name: proxy-net
    state: started
    restart_policy: unless-stopped

- name: Wait for green container health
  community.docker.docker_container_info:
    name: openclaw-green
  register: green_info
  until: green_info.container.State.Health.Status == "healthy"
  retries: 30
  delay: 10

- name: Switch Caddyfile upstream to green
  ansible.builtin.template:
    src: Caddyfile.j2
    dest: /etc/caddy/Caddyfile
    mode: "0644"
    backup: true
    validate: caddy validate --config %s
  vars:
    openclaw_upstream: "openclaw-green:3000"
  notify: Reload Caddy

- name: Verify traffic reaches green container
  ansible.builtin.uri:
    url: "https://{{ domain }}/health"
    status_code: 200
    timeout: 30
  retries: 5
  delay: 6

- name: Remove blue container
  community.docker.docker_container:
    name: openclaw-blue
    state: absent

- name: Rename green to canonical name
  ansible.builtin.command:
    cmd: docker rename openclaw-green openclaw
  changed_when: true
```

**Rollback (`roles/openclaw-deploy/tasks/rollback.yml`):**

```yaml
# Restores the previous image version when a green deploy fails post-cutover.
# Requires openclaw_previous_version to be set via group_vars or --extra-vars.

- name: Pull previous image
  community.docker.docker_image:
    name: "ghcr.io/openclaw/openclaw:{{ openclaw_previous_version }}"
    source: pull
    force_source: false

- name: Remove failed green container
  community.docker.docker_container:
    name: openclaw-green
    state: absent
  ignore_errors: true

- name: Restore canonical container from previous image
  community.docker.docker_container:
    name: openclaw
    image: "ghcr.io/openclaw/openclaw:{{ openclaw_previous_version }}"
    networks:
      - name: openclaw-net
      - name: proxy-net
    state: started
    restart_policy: unless-stopped

- name: Restore Caddyfile upstream to canonical container
  ansible.builtin.template:
    src: Caddyfile.j2
    dest: /etc/caddy/Caddyfile
    mode: "0644"
    backup: false
    validate: caddy validate --config %s
  vars:
    openclaw_upstream: "openclaw:3000"
  notify: Reload Caddy

- name: Log rollback event
  ansible.builtin.debug:
    msg: >-
      Rolled back from {{ openclaw_version }} to
      {{ openclaw_previous_version }} at {{ ansible_date_time.iso8601 }}
```

**Canary rollout (traffic split via Caddy):**

```caddy
# /etc/caddy/Caddyfile — canary: 10% to new version, 90% to stable
openclaw.yourdomain.com {
    reverse_proxy {
        to openclaw-stable:3000
        to openclaw-canary:3000

        lb_policy weighted_round_robin 9 1
    }
}
```

---

### 7. Observability & Monitoring

**Signals to instrument for an Ansible deployment pipeline:**

| Signal | Tool | Where |
| --- | --- | --- |
| Deploy duration | GitHub Actions built-in metrics | Actions → Insights |
| Deploy failure rate | `notify-deploy-failure.yml` (`workflow_run`) | Slack + GitHub Issues |
| Host health post-deploy | Health check step in `deploy.yml` | Actions logs |
| Ansible task failures | ansible-lint SARIF → GitHub Security tab | Security → Code scanning |
| Configuration drift | Drift detection cron (see §5) | GitHub Issues |
| Playbook execution traces | OpenTelemetry callback → Grafana Tempo | Grafana dashboard |

**`notify-deploy-failure.yml` — `workflow_run` failure alerts:**

```yaml
# .github/workflows/notify-deploy-failure.yml
# Triggered when the Deploy workflow completes. Notifies Slack on failure
# without blocking the deploy pipeline itself. Runs in a separate workflow
# so it has access to secrets even if the source workflow lacked them.

name: Notify Deploy Failure

on:
  workflow_run:
    workflows: ["Deploy"]
    types: [completed]

jobs:
  notify:
    runs-on: ubuntu-24.04
    if: github.event.workflow_run.conclusion == 'failure'
    permissions:
      contents: read

    steps:
      - name: Notify Slack
        uses: slackapi/slack-github-action@37ebaef184d7626c5f204ab8d3baff4262dd30f0  # v2.1.0
        with:
          payload: |
            {
              "text": ":x: Deploy failed on *${{ github.event.workflow_run.head_branch }}*",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Deploy Failed*\n*Branch:* ${{ github.event.workflow_run.head_branch }}\n*Actor:* ${{ github.event.workflow_run.triggering_actor.login }}\n*Run:* <${{ github.event.workflow_run.html_url }}|View failed run>"
                }
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          SLACK_WEBHOOK_TYPE: INCOMING_WEBHOOK
```

**OpenTelemetry callback configuration (`ansible.cfg`):**

```ini
[defaults]
# Emit OpenTelemetry spans for every Ansible task.
# Wire to Grafana Agent → Grafana Tempo for flame graphs of playbook runs.
# community.general collection required (already in requirements.yml).
callbacks_enabled = community.general.opentelemetry

[callback_opentelemetry]
# gRPC endpoint for the OTLP collector (Grafana Agent or otel-collector).
otel_exporter_otlp_endpoint = http://localhost:4317
# Emit spans at task granularity, not just play-level.
enable_from_tasks = True
# Redact task arguments to avoid leaking values from vault-sourced vars.
hide_task_arguments = True
```

---

### 8. Optimization (Cost, Speed, Sustainability)

**Speed:**

- **Cache pip installs** — `actions/setup-python` with `cache: pip` cuts install time by ~40s per job
- **Cache Galaxy collections** — hash on `requirements.yml`; saves ~60s when unchanged
- **`cancel-in-progress: true`** — never run CI on a superseded push
- **Molecule `--parallel`** — run scenarios in parallel when driver supports it
- **Self-hosted runner** — a runner co-located with the target server eliminates SSH round-trip latency; a `t3.micro` next to the VPS reduces deploy time by 30–60s

**Cost:**

- GitHub-hosted `ubuntu-24.04` runners cost $0.008/minute (2026 pricing). A typical Ansible CI run (lint + molecule) is ~6 minutes = ~$0.05/run.
- Self-hosted runner on the same VPS: $0/run after fixed compute cost.
- Cache usage reduces billed minutes; matrix parallelism reduces wall-clock time without reducing billed minutes.

**Sustainability:**

- `ubuntu-24.04` (x64) has a lower energy footprint than larger runner types.
- `concurrency: cancel-in-progress` avoids burning minutes on abandoned work.
- Molecule Docker driver reuses images across scenarios — set `pre_build_image: true` where possible.

---

### 9. AI Assistance (GitHub Copilot for Workflows)

**Copilot Workspace + Actions in 2026:**

- **Copilot in the editor**: Autocompletes Ansible task blocks, suggests FQCN module names, and flags `no_log` omissions inline in VS Code / JetBrains.
- **Copilot Chat `/fix`**: Paste an ansible-lint error → Copilot suggests the corrected task. Useful for FQCN migrations.
- **Copilot for Pull Requests**: Generates PR descriptions summarizing which roles changed and what tasks were added — reduces reviewer cognitive load.
- **GitHub Actions Copilot**: In the Actions editor, Copilot suggests complete workflow YAML from a natural language description. Effective for bootstrapping reusable workflows.
- **Custom Copilot Instructions** (`.github/copilot-instructions.md`):

```markdown
# Copilot Instructions — clincher (Ansible)

- Always use FQCN for module names (ansible.builtin., community.docker., etc.)
- All tasks need `name:` descriptions starting with a verb
- Secrets must use ansible-vault; never hardcode credentials
- Prefer `community.docker.docker_container` over `ansible.builtin.command: docker run`
- Every role must have a corresponding Molecule scenario in molecule/<role>/
- Use `become: true` only at the task level, never at the play level
- Shell/command tasks must include `changed_when:` to avoid always-changed
```

---

### 10. Documentation & Automation (GitHub Projects Tracking)

**Issue templates (`.github/ISSUE_TEMPLATE/deploy-failure.yml`):**

```yaml
name: Deploy Failure
description: Report a failed deployment
labels: ["deploy-failure", "incident"]
body:
  - type: dropdown
    id: environment
    attributes:
      label: Environment
      options: [staging, production]
    validations:
      required: true
  - type: input
    id: run-url
    attributes:
      label: GitHub Actions run URL
    validations:
      required: true
  - type: textarea
    id: error-output
    attributes:
      label: Error output
      render: shell
```

**GitHub Projects automation:**

- Create a Project with columns: `Backlog → In Progress → Staged → Released`
- Add automation: PR merged to `main` → move to `Staged`; tag pushed → move to `Released`
- Link the drift detection issue template to auto-add to `Backlog`

**PR template (`.github/pull_request_template.md`):**

```markdown
## Summary

<!-- What does this PR change? Which roles/tasks? -->

## Test Plan

- [ ] `ansible-lint --profile production` passes locally
- [ ] `molecule test` passes for affected roles
- [ ] `ansible-playbook --syntax-check` passes
- [ ] Tested against staging with `--check --diff` before merging

## Security Checklist

- [ ] No secrets in plaintext — vault-encrypted or omitted
- [ ] `no_log: true` on all tasks handling sensitive data
- [ ] `become: true` scoped to task level only
- [ ] New Galaxy dependencies reviewed for known CVEs
```

---

## Comprehensive Checklist

### Security

- [ ] All GitHub Actions pinned to commit SHA (not tag)
- [ ] `GITHUB_TOKEN` permissions set to minimum required per workflow
- [ ] OIDC used for all cloud/vault authentication — no long-lived secrets in repo settings
- [ ] `ansible-vault` encrypts all secrets; `vault.yml.example` committed, `vault.yml` gitignored
- [ ] `no_log: true` on every task touching credentials or tokens
- [ ] Dependabot enabled for `github-actions` and `pip` ecosystems
- [ ] Renovate Bot configured for Galaxy collection version bumps (`renovate.json`)
- [ ] CodeQL enabled on `main` and weekly schedule
- [ ] Branch protection: PR required, CI required, admin bypass disabled
- [ ] GitHub Environments: `production` requires 1 named reviewer with deployment branch rule
- [ ] Secret scanning enabled in repository settings
- [ ] `.gitignore` includes `vault.yml`, `*.key`, `*.pem`, `.env`

### Performance

- [ ] `concurrency: cancel-in-progress: true` in all CI workflows
- [ ] pip cache enabled via `actions/setup-python` `cache: pip`
- [ ] Galaxy collections cached on `hashFiles('requirements.yml')`
- [ ] Matrix strategy used for Molecule multi-scenario runs
- [ ] Self-hosted runner evaluated if deploy latency is a concern

### Reliability

- [ ] `fail-fast: false` in matrix jobs (one failure doesn't cancel siblings)
- [ ] Molecule tests cover all roles with at least `default` and `hardened` scenarios
- [ ] `_syntax.yml` defined and referenced correctly from `ci.yml`
- [ ] Drift detection cron opens GitHub issue on non-idempotent state
- [ ] Post-deploy health check step in `deploy.yml`
- [ ] Rollback tasks defined in `roles/openclaw-deploy/tasks/rollback.yml`
- [ ] Ansible `serial:` set for rolling updates if managing multiple hosts later
- [ ] `--diff` flag used in all deploy runs for auditability

---

## Common Pitfalls & Fixes

| Pitfall | Symptom | Fix |
| --- | --- | --- |
| Tag drift in Actions | Supply-chain compromise via mutable tags | Pin every `uses:` to commit SHA; use Dependabot to update SHAs |
| `ansible-vault` password in plaintext | Vault password visible in workflow logs | Use `--vault-password-file <(echo "$SECRET")` — process substitution keeps it out of argv |
| Molecule not testing idempotency | Role applies changes on every run | Run `converge` twice; assert no changes on second run |
| `become: true` at play level | Entire play runs as root | Move `become: true` to individual privileged tasks only |
| Missing `changed_when` on `command` tasks | Always reports changed; breaks idempotency | Add `changed_when: false` or parse stdout to detect actual change |
| Hardcoded inventory IPs | Real server IPs in git history | Use `ansible_host: "{{ server_ip }}"` in `hosts.yml`; set `server_ip` in vault |
| EE base image not pinned to digest | Silent upstream updates break reproducibility | Use `name: ghcr.io/ansible/community-ee-minimal@sha256:<digest>` |
| Production deploy without staging gate | Untested change goes to prod | `deploy-production` must `needs: deploy-staging` |
| Missing `_syntax.yml` definition | Workflow fails with "Could not find reusable workflow" | Define `_syntax.yml` (see §2) |
| Blue-green cutover without verify step | Broken green container serves traffic | Add `ansible.builtin.uri` health check before removing blue container |

---

## Recommended Stack by Project Type

| Scenario | Controller | Secrets | Registry | Monitoring |
| --- | --- | --- | --- | --- |
| Single VPS (this project) | GitHub Actions + self-hosted runner on VPS | HashiCorp Vault (OIDC) | GHCR | Prometheus + Grafana (role: monitoring) |
| Multi-host bare metal | AWX / AAP 2.5 | Vault or CyberArk | Quay.io | ELK stack or Grafana Cloud |
| Cloud-native (AWS) | GitHub Actions (ubuntu-24.04) | AWS Secrets Manager (OIDC) | ECR | CloudWatch + Grafana |
| Air-gapped / on-prem | Gitea + Gitea Actions | HashiCorp Vault (offline) | Harbor | Prometheus + Alertmanager |

---

## Future-Proofing Tips

1. **Migrate to Ansible Execution Environments now** — AAP 2.5+ requires EEs; virtualenvs are deprecated in the automation platform. Getting `execution-environment.yml` in place today means zero friction when you move to AWX.

2. **OpenTelemetry for Ansible** — the `community.general.opentelemetry` callback emits traces for every task. Wire it to Grafana Tempo to get flame graphs of playbook execution time. This becomes critical when playbooks grow past 200 tasks.

3. **Renovate Bot over Dependabot for Galaxy** — Dependabot does not natively update `requirements.yml` Galaxy collection versions as of March 2026. Renovate Bot with the `ansible-galaxy` datasource handles this. The `renovate.json` in §5 is ready to commit.

4. **Merge queues** — enable GitHub Merge Queue (`Settings → General → Merge Queue`) once the team grows. The queue serializes merges and re-runs CI on the combined commit before merging, eliminating "passing CI then merging broke main" incidents.

5. **GitHub Actions OIDC → Ansible Vault** — the OIDC → Vault pattern shown in `deploy.yml` is the current best practice. Watch for AWS IAM Roles Anywhere and Azure Workload Identity as cloud-native alternatives without running Vault.

6. **Pin `ansible-core` in `requirements.txt`** — `ansible-core` minor releases have broken backward compatibility. Pin to `==2.20.x` and use Renovate to bump deliberately, not silently.
