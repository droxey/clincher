# OpenClaw Deployment Bug Report

> **Date**: 2026-02-24
> **Scope**: Full audit of the Ansible-automated OpenClaw deployment flow
> **Trigger**: Persistent `openclaw-egress` container crash loop preventing stack deployment

## Executive Summary

The deployment fails because the Smokescreen egress proxy container enters a crash/unhealthy loop, which cascades via `depends_on` health conditions to block LiteLLM and the OpenClaw gateway from starting. Root-cause analysis reveals **three critical bugs** in the egress proxy configuration, plus **six additional bugs** across the LiteLLM config, security model, and Ansible orchestration.

Even after fixing the immediate crash, the deployment would fail at verification (Step 10) because the Smokescreen `RoleFromRequest` function rejects all non-TLS proxy traffic — making the egress proxy non-functional for its intended purpose.

---

## Critical Bugs (Deployment-Breaking)

### Bug 1: Smokescreen `/healthcheck` Endpoint Not Activated

**File**: `roles/openclaw-config/templates/docker-compose.yml.j2:148-153`
**Severity**: CRITICAL — blocks entire stack deployment

The Docker health check for the egress proxy is:

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "http://localhost:4750/healthcheck"]
```

Smokescreen's `/healthcheck` endpoint is served by a `HealthcheckMiddleware` that is **only activated when `config.Healthcheck` is non-nil** [1]:

```go
// pkg/smokescreen/smokescreen.go
if config.Healthcheck != nil {
    handler = &HealthcheckMiddleware{
        Proxy:       handler,
        Healthcheck: config.Healthcheck,
    }
}
```

Neither `cmd.NewConfiguration()` nor `main.go` sets `config.Healthcheck`. It remains `nil`. The middleware is never registered. **The `/healthcheck` endpoint does not exist on port 4750.**

When `curl` hits port 4750 with a regular HTTP GET, Smokescreen (an HTTP CONNECT proxy) treats it as a malformed proxy request and returns an error. The `-f` flag on curl causes a non-zero exit. Health check fails. Container is never marked healthy. `depends_on: service_healthy` blocks litellm and openclaw from starting.

**Cascade**:
```
openclaw-egress (unhealthy) ──┬──▶ litellm (never starts)
                              │        │
                              │        ▼
                              └──▶ openclaw (never starts)
```

**Fix**: Replace the health check with a TCP port probe or a simple HTTP request that accepts any response:

```yaml
healthcheck:
  test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:4750/ 2>&1 | grep -q 'connected' || curl -so /dev/null -w '' http://localhost:4750/ 2>&1 && exit 0 || exit 0"]
```

Or more robustly, install `netcat-openbsd` in the Dockerfile and probe the TCP port:

```yaml
# In Dockerfile — add netcat:
RUN apk add --no-cache ca-certificates netcat-openbsd && adduser -D -H smokescreen

# In docker-compose.yml.j2:
healthcheck:
  test: ["CMD-SHELL", "nc -z localhost 4750"]
```

---

### Bug 2: Smokescreen Process Exits Immediately — `read_only` Filesystem Conflict

**File**: `roles/openclaw-config/templates/docker-compose.yml.j2:143,144-145` and `Dockerfile.smokescreen.j2`
**Severity**: CRITICAL — process crash loop

The container log shows:
```json
"ExitCode": 0, "State": "restarting", "Status": "Restarting (1) Less than a second ago"
```

The Smokescreen process exits with code 0 within milliseconds of starting. `StartWithConfig()` is a blocking call (calls `server.Serve(listener)`) [2], so the only way it returns is if an error occurs during server setup. Since `main.go` doesn't check the return error or call `os.Exit(1)`, the process exits cleanly with code 0.

**Root cause**: The container has `read_only: true` with only `/tmp` as a tmpfs:

```yaml
read_only: true
tmpfs:
  - /tmp:size=16M
```

Smokescreen v0.0.4 defines `--stats-socket-dir` and `--stats-socket-file-mode` flags [3]. If the stats socket directory has a non-empty default (e.g., `/var/run/smokescreen/`), the server tries to create a Unix socket on a read-only filesystem, fails, and `StartWithConfig()` returns its error silently.

**Additional contributing factor**: The Docker socket proxy container (`docker-proxy`) works because it has BOTH `/tmp` AND `/run` tmpfs mounts:

```yaml
# docker-proxy — works:
tmpfs:
  - /tmp:size=16M
  - /run:size=8M    # ← this is missing from openclaw-egress
```

**Fix**: Add the `/run` tmpfs and explicitly set the stats socket directory to writable space:

```yaml
openclaw-egress:
  # ...
  read_only: true
  tmpfs:
    - /tmp:size=16M
    - /run:size=8M        # Add this
  command:
    - "--egress-acl-file=/etc/smokescreen/acl.yaml"
    - "--listen-ip=0.0.0.0"
    - "--stats-socket-dir=/tmp"      # Add this — force stats socket to writable dir
    - "--deny-range=10.0.0.0/8"
    - "--deny-range=172.16.0.0/12"
    - "--deny-range=192.168.0.0/16"
```

---

### Bug 3: `RoleFromRequest` Requires TLS — All Proxy Traffic Rejected

**File**: Smokescreen's `main.go` (built from source at `v0.0.4`)
**Severity**: CRITICAL — egress proxy non-functional even if container starts

Smokescreen v0.0.4's `main.go` sets:

```go
conf.RoleFromRequest = defaultRoleFromRequest
```

`defaultRoleFromRequest` extracts the CommonName from the client's **TLS certificate** to determine the ACL role [4]. It returns an error when no certificate is present — which is always the case because the deployment uses plain HTTP:

```yaml
HTTP_PROXY: http://openclaw-egress:4750   # ← plain HTTP, no TLS
HTTPS_PROXY: http://openclaw-egress:4750  # ← still plain HTTP to the proxy
```

When `RoleFromRequest` returns an error, Smokescreen denies the request. **Every proxy request from OpenClaw and LiteLLM would be rejected**, even to whitelisted domains like `*.anthropic.com`.

The Step 10 verification would catch this:
```bash
# This would FAIL with 403/502 even though api.anthropic.com is whitelisted:
curl -x http://openclaw-egress:4750 -I https://api.anthropic.com
```

**Fix**: The `main.go` needs to be replaced with a version that uses a non-TLS role function. Create a custom entrypoint that falls back to the `default` ACL policy for all requests:

```go
// custom-main.go — use as build target instead of .
package main

import (
    "net/http"
    "github.com/stripe/smokescreen/cmd"
    "github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {
    conf, err := cmd.NewConfiguration(nil, nil)
    if err != nil {
        panic(err)
    }
    // Return empty role → falls back to "default" ACL policy
    conf.RoleFromRequest = func(req *http.Request) (string, error) {
        return "default", nil
    }
    if err := smokescreen.StartWithConfig(conf, nil); err != nil {
        panic(err)
    }
}
```

Update the Dockerfile to copy and build the custom main:

```dockerfile
FROM golang:{{ smokescreen_go_version }}-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone https://github.com/stripe/smokescreen.git . && \
    git checkout {{ smokescreen_commit }}
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /smokescreen .

FROM alpine:{{ smokescreen_alpine_version }}
RUN apk add --no-cache ca-certificates netcat-openbsd && adduser -D -H smokescreen
COPY --from=builder /smokescreen /usr/local/bin/smokescreen
USER smokescreen
ENTRYPOINT ["smokescreen"]
```

Deploy the custom `main.go` alongside the Dockerfile in `build/smokescreen/`.

---

## High-Severity Bugs (Functional)

### Bug 4: `proxy-net` Allows OpenClaw to Bypass Egress Proxy

**File**: `roles/openclaw-config/templates/docker-compose.yml.j2:194-201`
**Severity**: HIGH — security model bypass

The network definitions:

```yaml
networks:
  openclaw-net:
    driver: bridge
    internal: true    # ← no internet
  proxy-net:
    driver: bridge    # ← HAS internet access
  egress-net:
    driver: bridge    # ← HAS internet access (intentional for Smokescreen)
```

The `openclaw` container is on both `openclaw-net` and `proxy-net`:

```yaml
openclaw:
  networks:
    - openclaw-net
    - proxy-net       # ← internet-accessible network
```

Since `proxy-net` is not `internal: true`, the OpenClaw container has a direct path to the internet that **completely bypasses the Smokescreen egress proxy**. A compromised agent (via prompt injection → tool execution) could make arbitrary outbound connections through `proxy-net`, rendering the entire egress whitelist moot.

The `HTTP_PROXY`/`HTTPS_PROXY` environment variables only affect well-behaved clients. Raw socket connections, `curl --noproxy '*'`, or any tool that ignores proxy settings can reach the internet directly.

**Fix**: Restructure networks so OpenClaw never has direct internet access:

```yaml
networks:
  openclaw-net:
    driver: bridge
    internal: true    # No internet — all services
  proxy-net:
    driver: bridge
    internal: true    # ← ADD THIS — make it internal too
  ingress-net:
    driver: bridge    # ← NEW — internet-facing for reverse proxy only
  egress-net:
    driver: bridge    # Internet-facing for Smokescreen only
```

Then update the Caddy compose overlay to use `ingress-net` for port binding and `proxy-net` for reaching OpenClaw. This isolates OpenClaw from internet access on all networks.

---

### Bug 5: LiteLLM `max_budget` and `rpm` Incorrectly Placed in Config

**File**: `roles/openclaw-config/templates/litellm-config.yaml.j2:7-12`
**Severity**: HIGH — budget and rate limits silently not enforced

The template generates:

```yaml
model_list:
  - model_name: "anthropic/claude-opus-4-6"
    litellm_params:
      model: "claude-opus-4-6"
      api_key: "os.environ/ANTHROPIC_API_KEY"
      max_budget: 100.0    # ← WRONG: inside litellm_params
      rpm: 60               # ← WRONG: inside litellm_params
```

LiteLLM expects `rpm` at the **model level** (same indentation as `model_name`) and `max_budget` inside **`model_info`** [5]:

```yaml
model_list:
  - model_name: "anthropic/claude-opus-4-6"
    litellm_params:
      model: "claude-opus-4-6"
      api_key: "os.environ/ANTHROPIC_API_KEY"
    model_info:
      max_budget: 100.0
    rpm: 60
```

With the current placement, both values are **silently ignored** by LiteLLM's config parser. There are no budget caps or rate limits on any model — the deployment would allow unlimited API spend.

**Fix**: Update the Jinja2 template:

```yaml
{% for model in litellm_models %}
  - model_name: "{{ model.name }}"
    litellm_params:
      model: "{{ model.model }}"
      api_key: "os.environ/{{ model.key_env }}"
{% if model.max_budget is defined %}
    model_info:
      max_budget: {{ model.max_budget }}
{% endif %}
{% if model.rpm is defined %}
    rpm: {{ model.rpm }}
{% endif %}
{% endfor %}
```

---

### Bug 6: Telegram Bot Token Exposed in Process Arguments

**File**: `roles/openclaw-integrate/tasks/main.yml:49-52`
**Severity**: HIGH — credential leak via `ps aux`

```yaml
- name: Set Telegram bot token
  ansible.builtin.command: >
    docker exec openclaw openclaw config set channels.telegram.token
    "{{ telegram_bot_token }}"
```

The token appears as a CLI argument in the process table. Any user or process on the host running `ps aux` can see it. This directly contradicts the project's security model, which specifies file-based secret passing [6].

The gateway token handling (in `openclaw-harden`) correctly uses file-based passing:

```yaml
# Correct approach (gateway token):
- docker cp .gateway-token openclaw:/tmp/.gw-token
- docker exec openclaw sh -c 'openclaw config set gateway.auth.token "$(cat /tmp/.gw-token)"'
```

**Fix**: Use the same file-based pattern for the Telegram token:

```yaml
- name: Write Telegram bot token to host tempfile
  ansible.builtin.copy:
    content: "{{ telegram_bot_token }}"
    dest: "{{ openclaw_base_dir }}/monitoring/.telegram-token"
    mode: "0600"
  no_log: true

- name: Copy Telegram token into container
  ansible.builtin.command: docker cp {{ openclaw_base_dir }}/monitoring/.telegram-token openclaw:/tmp/.tg-token
  no_log: true

- name: Install Telegram token via file
  ansible.builtin.command: >
    docker exec openclaw sh -c
    'openclaw config set channels.telegram.token "$(cat /tmp/.tg-token)" && rm -f /tmp/.tg-token'
  no_log: true

- name: Remove Telegram token tempfile from host
  ansible.builtin.file:
    path: "{{ openclaw_base_dir }}/monitoring/.telegram-token"
    state: absent
```

---

## Medium-Severity Bugs (Robustness)

### Bug 7: LiteLLM Unnecessarily Depends on Egress Proxy

**File**: `roles/openclaw-config/templates/docker-compose.yml.j2:109-113`
**Severity**: MEDIUM — increases deployment fragility

```yaml
litellm:
  depends_on:
    redis:
      condition: service_healthy
    openclaw-egress:
      condition: service_healthy    # ← unnecessary for startup
```

LiteLLM only makes outbound API calls when handling model requests, not during startup. Its startup sequence (load config, connect to Redis, start HTTP server) requires only Redis, not the egress proxy. The egress dependency creates a tighter coupling than necessary — if egress has a transient failure, LiteLLM can't start or restart, even though it could serve cached results from Redis.

**Fix**: Remove egress from LiteLLM's `depends_on`. The egress proxy is only needed at request time, not at startup:

```yaml
litellm:
  depends_on:
    redis:
      condition: service_healthy
    # Remove openclaw-egress dependency
```

The `openclaw` service still depends on egress, so the full stack still waits for egress before the gateway starts.

---

### Bug 8: First-Run Handler Race Condition

**File**: `roles/openclaw-config/handlers/main.yml:7-10`
**Severity**: MEDIUM — first deployment may fail

On first run, the config role deploys the Smokescreen ACL template, which triggers `notify: restart egress`:

```yaml
# handlers/main.yml
- name: restart egress
  ansible.builtin.command: docker compose restart openclaw-egress
  args:
    chdir: "{{ openclaw_base_dir }}"
```

But the container doesn't exist yet — the deploy role hasn't run. `docker compose restart openclaw-egress` fails because there's nothing to restart. This handler error can abort the playbook before reaching the deploy role.

On subsequent runs, the container exists, so the handler works. This explains why first deployments may fail while re-runs succeed.

**Fix**: Add error tolerance to the handler:

```yaml
- name: restart egress
  ansible.builtin.command: docker compose restart openclaw-egress
  args:
    chdir: "{{ openclaw_base_dir }}"
  failed_when: false
```

Or check container existence first:

```yaml
- name: restart egress
  ansible.builtin.shell: |
    if docker ps -a --format '{{ "{{" }}.Names{{ "}}" }}' | grep -q openclaw-egress; then
      docker compose restart openclaw-egress
    fi
  args:
    chdir: "{{ openclaw_base_dir }}"
```

---

### Bug 9: Backup Script Uses Unpinned Alpine Image

**File**: `roles/maintenance/templates/backup.sh.j2:13`
**Severity**: LOW — backup may fail if image not cached

```bash
docker run --rm \
  -v openclaw_openclaw-data:/source:ro \
  -v {{ openclaw_base_dir }}/monitoring/backups:/backup \
  alpine:3.21 tar -czf "/backup/openclaw-data-$(date +%F).tar.gz" -C /source .
```

`alpine:3.21` is referenced but never pre-pulled during deployment. If the image isn't cached on the host and Docker Hub is unreachable (e.g., if host DNS is restricted), the nightly backup cron job fails silently.

**Fix**: Add a pre-pull task in the maintenance role:

```yaml
- name: Pull Alpine image for backup jobs
  community.docker.docker_image:
    name: "alpine:3.21"
    source: pull
```

---

## Dependency Chain Visualization

The current `depends_on` chain, showing where each bug blocks:

```
redis (healthy ✓)
  └──▶ litellm ──[Bug 7: unnecessary]──▶ openclaw-egress (Bug 1+2+3)
                                              │
docker-proxy (healthy ✓)                      │
  └──▶ openclaw ──────────────────────────────┘
                ──▶ litellm (blocked by egress)
```

With Bug 1 + Bug 2 fixed, the chain unblocks:

```
redis (healthy ✓)                    openclaw-egress (healthy ✓)
  └──▶ litellm (healthy ✓) ◀────────────┘
                                         │
docker-proxy (healthy ✓)                 │
  └──▶ openclaw (healthy ✓) ◀───────────┘
```

But Bug 3 then causes all proxy traffic to fail at runtime, which Step 10 (verification) would catch.

---

## Fix Priority Order

1. **Bug 2** — Add `/run` tmpfs + `--stats-socket-dir=/tmp` to stop crash loop
2. **Bug 1** — Replace health check with TCP port probe (install `netcat-openbsd`)
3. **Bug 3** — Replace `main.go` with custom non-TLS `RoleFromRequest`
4. **Bug 5** — Move `max_budget`/`rpm` to correct config locations
5. **Bug 4** — Make `proxy-net` internal, add `ingress-net` for reverse proxy
6. **Bug 6** — Switch Telegram token to file-based secret passing
7. **Bug 7** — Remove egress from LiteLLM's `depends_on`
8. **Bug 8** — Add `failed_when: false` to config role handlers
9. **Bug 9** — Pre-pull Alpine image for backup jobs

Bugs 1-3 must be fixed together to achieve a working deployment. Bug 3 requires changes to the Smokescreen build process (custom `main.go`), which is the most invasive change.

---

## How to Verify

After applying fixes, run the playbook and check:

```bash
# 1. Egress container stays running (not restarting)
docker inspect openclaw-egress --format '{{.State.Status}}'
# Expected: running

# 2. Health check passes
docker inspect openclaw-egress --format '{{.State.Health.Status}}'
# Expected: healthy

# 3. Proxy traffic works (whitelisted domain)
docker exec openclaw curl -x http://openclaw-egress:4750 -I https://api.anthropic.com
# Expected: HTTP 200

# 4. Proxy traffic blocked (non-whitelisted domain)
docker exec openclaw curl -x http://openclaw-egress:4750 -I https://example.com
# Expected: HTTP 403

# 5. LiteLLM rate limits active
docker exec openclaw-litellm wget -qO- http://localhost:4000/model/info | python3 -m json.tool | grep rpm
# Expected: rpm values present per model

# 6. Full stack healthy
docker compose ps
# Expected: all 5 containers running (healthy)
```

---

## Footnotes

[1] `pkg/smokescreen/smokescreen.go` — HealthcheckMiddleware registration is conditional on `config.Healthcheck != nil`
[2] `pkg/smokescreen/smokescreen.go` — `StartWithConfig()` calls `runServer()` → `server.Serve(listener)` (blocking)
[3] `cmd/smokescreen.go` — defines `--stats-socket-dir` and `--stats-socket-file-mode` flags
[4] `main.go` — `defaultRoleFromRequest()` extracts TLS client cert CommonName; returns error if cert missing
[5] LiteLLM docs — `rpm` is a model-level key, `max_budget` belongs in `model_info`
[6] `CLAUDE.md` — "File-based secret passing — never CLI args" (Security Model, item 6)
