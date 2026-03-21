# Security Model

> Defense-in-depth architecture for hardened AI agent deployment.

---

## Overview

Defense-in-depth: socket proxy, egress whitelist (Smokescreen), `openclaw-net` internal bridge, `cap_drop: ["ALL"]` on all infrastructure containers and sandboxes, `no-new-privileges` enforced at daemon and container level, 13 dangerous tools blocked, file-based secret passing, SSH hardened (no root, no forwarding, deploy user only), UFW + fail2ban, Cloudflare-only ingress.

## Verification Commands

```bash
# Verify your deployment passes the full security audit
docker exec $(docker ps -q -f "name=openclaw") openclaw security audit --deep

# Inspect sandbox isolation status
docker exec $(docker ps -q -f "name=openclaw") openclaw sandbox explain
```

## Layer Details

### 1. Network Isolation

The `openclaw-net` bridge network is configured with `internal: true`, which means containers on this network have no direct internet access. All core services (OpenClaw gateway, Docker socket proxy, LiteLLM, Redis, and the egress proxy) communicate exclusively over this internal bridge. Traffic can only leave through the egress proxy, which bridges `openclaw-net` and `egress-net`.

### 2. Egress Control

[Smokescreen](https://github.com/stripe/smokescreen) acts as an HTTPS-only egress whitelist proxy. Only explicitly whitelisted LLM provider domains (e.g., `*.anthropic.com`, `*.openai.com`) are permitted. Each whitelisted domain is a potential data-exfiltration channel, so the allowlist should be kept minimal. LiteLLM routes all outbound API calls through Smokescreen via the `HTTP_PROXY` environment variable.

### 3. Socket Proxy

The Docker socket proxy (`docker-socket-proxy`) exposes a limited subset of the Docker API: `EXEC`, `CONTAINERS`, `IMAGES`, `INFO`, `VERSION`, `PING`, and `EVENTS` only. Dangerous endpoints are explicitly denied: `BUILD`, `SECRETS`, and `SWARM`. This prevents the agent runtime from performing privileged Docker operations even if it gains access to the socket proxy.

### 4. Container Hardening

All infrastructure containers run with `cap_drop: ["ALL"]`, removing every Linux capability. The `no-new-privileges` security option is enforced at both the Docker daemon level and per-container, preventing processes from gaining additional privileges via `setuid` binaries or other escalation mechanisms.

### 5. Sandbox Isolation

Agent sandbox containers are configured with:

- `capDrop: ["ALL"]` — no Linux capabilities
- `network: "none"` — no network access whatsoever
- `workspaceAccess: "none"` — no access to the host workspace
- Resource caps: 1 GB memory, 1.0 CPU, 512 PIDs limit per sandbox
- Lifecycle limits: 12-hour idle timeout, 3-day maximum age
- Maximum 8 concurrent sandboxes (8 GB total sandbox memory on a 64 GB host)

### 6. Tool Denials

13 dangerous tools are blocked at both the agent and gateway levels:

- **Agent-level denials**: `process`, `browser`, `nodes`, `gateway`, `sessions_spawn`, `sessions_send`, `elevated`, `host_exec`, `docker`, `camera`, `canvas`, `cron`
- **Gateway-level denials**: `sessions_spawn`, `sessions_send`, `gateway`, `elevated`, `host_exec`, `docker`, `camera`, `canvas`, `cron`

The dual-layer denial ensures tools are blocked even if an agent-level configuration is bypassed.

### 7. Credential Handling

All secrets are passed via file-based mechanisms, never as CLI arguments. CLI arguments appear in process tables (`/proc/*/cmdline`) and are visible to any user on the host. File-based passing uses `docker cp` to transfer secret files into containers, which are then read and deleted. Secret files are created with `chmod 600` permissions.

### 8. SSH Hardening

- Non-standard SSH port (reduces automated scanning noise)
- Key-only authentication (password auth disabled)
- Login restricted to the `deploy` user only (no root SSH)
- All forwarding disabled (no agent, X11, or TCP forwarding)

### 9. Firewall

- **UFW**: Default deny inbound, allow only SSH (custom port) and HTTPS (443)
- **fail2ban**: Automated IP banning after repeated failed authentication attempts
- **Cloudflare-only ingress**: UFW rules restrict port 443 to Cloudflare IP ranges, preventing direct-to-origin attacks. Admin IP whitelist provides direct access for maintenance.

## Threat Model

The primary threat vector is: **prompt injection → arbitrary tool execution → host/container escape**.

1. **Prompt injection**: A malicious user crafts input that causes the agent to ignore its system prompt (SOUL.md) and execute unintended actions.
2. **Arbitrary tool execution**: If injection succeeds, the attacker attempts to invoke dangerous tools (file system access, network calls, Docker operations).
3. **Host/container escape**: With tool access, the attacker attempts to break out of the sandbox container to reach the host system or other containers.

Each security layer addresses a stage in this chain:

- SOUL.md rules and model selection (Opus over Haiku) reduce injection success rates
- Tool denials block dangerous tools even if injection succeeds
- Sandbox isolation (`network=none`, `capDrop=["ALL"]`) contains execution even if tool denials are bypassed
- Network isolation and egress control prevent lateral movement and data exfiltration
- Socket proxy limits prevent Docker API abuse

Additionally, the skill/agent onboarding checklist ensures that third-party prompts and skills are reviewed for hidden tool calls, excessive permissions, and egress impact before deployment.

---

For full implementation details, see the [deployment guide](../README.md) — specifically Step 5 (Gateway and Sandbox Hardening).
