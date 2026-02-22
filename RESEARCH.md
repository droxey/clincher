# OpenClaw Research — Deployment Plan Audit (2026.2)

> **Scope**: Web + X.com research (2026 sources only) cross-referenced against the `README.md` deployment plan.
> **OpenClaw version under review**: `openclaw/openclaw:2026.2.15`
> **Date**: 2026-02-17

---

## Table of Contents

- [1. OpenClaw Platform Overview](#1-openclaw-platform-overview)
  - [1.1 What OpenClaw Is](#11-what-openclaw-is)
  - [1.2 Architecture](#12-architecture)
  - [1.3 2026.2.x Release Timeline](#13-2026-2x-release-timeline)
  - [1.4 Ecosystem and Community](#14-ecosystem-and-community)
- [2. Capabilities — Including Esoteric Use Cases](#2-capabilities--including-esoteric-use-cases)
  - [2.1 Core Agent Capabilities](#21-core-agent-capabilities)
  - [2.2 Channel Integrations](#22-channel-integrations)
  - [2.3 Advanced and Esoteric Use Cases](#23-advanced-and-esoteric-use-cases)
- [3. Security Landscape](#3-security-landscape)
  - [3.1 CVEs and GHSAs](#31-cves-and-ghsas)
  - [3.2 Prompt Injection as Attack Vector](#32-prompt-injection-as-attack-vector)
  - [3.3 Supply Chain — ClawHub Skills Poisoning](#33-supply-chain--clawhub-skills-poisoning)
  - [3.4 Third-Party Security Tools](#34-third-party-security-tools)
- [4. Issues in the Current Deployment Plan](#4-issues-in-the-current-deployment-plan)
  - [4.1 Critical Issues](#41-critical-issues)
  - [4.2 High-Severity Issues](#42-high-severity-issues)
  - [4.3 Medium-Severity Issues](#43-medium-severity-issues)
  - [4.4 Low-Severity Issues](#44-low-severity-issues)
- [5. Missing Features](#5-missing-features)
  - [5.1 Security Features Not Configured](#51-security-features-not-configured)
  - [5.2 Operational Features Missing](#52-operational-features-missing)
  - [5.3 Platform Capabilities Not Leveraged](#53-platform-capabilities-not-leveraged)
- [6. Alternative Architectures Worth Considering](#6-alternative-architectures-worth-considering)
- [7. Recommendations Summary](#7-recommendations-summary)
- [Sources](#sources)

---

## 1. OpenClaw Platform Overview

### 1.1 What OpenClaw Is

OpenClaw (formerly Clawdbot, then Moltbot) is an open-source autonomous AI agent platform created by Peter Steinberger. It grants an LLM-powered agent near-total control over a host machine — file operations, shell commands, browser automation, API calls, and messaging — orchestrated through a single-process Gateway that multiplexes WebSocket and HTTP traffic.

As of early February 2026, OpenClaw surpassed **180,000 GitHub stars**, making it one of the fastest-growing open-source projects in GitHub history [10]. OpenAI subsequently hired Steinberger, with Aaron Levie commenting: "If anyone was wondering if 2026 was the year of agents, OpenAI is bringing on the maker of OpenClaw" [4].

### 1.2 Architecture

OpenClaw follows a **Gateway-centric** architecture:

```
Channels (WhatsApp, Discord, Telegram, Slack, Signal)
                    │
                    ▼
            ┌───────────────┐
            │   Gateway     │  ← Single process: WebSocket + HTTP + Control UI
            │  (port 18789) │
            └──────┬────────┘
                   │
        ┌──────────┼──────────────┐
        ▼          ▼              ▼
   Agent Router   Tool Engine   Memory (QMD/LanceDB)
        │          │              │
        ▼          ▼              ▼
   LLM Providers  Sandbox       Voyage AI embeddings
   (via proxy)    Containers    (optional)
```

Key architectural facts:
- **Single-process Gateway**: Multiplexes all protocols. No separate API server.
- **Multi-agent routing**: Routes messages to different agents based on channel, DM policy, and mention patterns.
- **Tool sandboxing**: Executes tools inside ephemeral Docker containers with dropped capabilities and no network by default.
- **Memory system**: Uses QMD (Quantized Memory Digest) with LanceDB for vector storage and Voyage AI for embeddings.
- **Plugin system**: In-process extensions that run with Gateway privileges.

### 1.3 2026.2.x Release Timeline

| Version | Date | Headline |
|---------|------|----------|
| 2026.2.1 | ~Feb 1 | Major post-rebrand release, agent safety focus [3] |
| 2026.2.6 | ~Feb 6 | Opus 4.6 + GPT-5.3-Codex, xAI Grok, Voyage AI memory, skill code safety scanner [2] |
| 2026.2.12 | ~Feb 12 | **40+ security vulnerabilities** patched, architectural stability [8] |
| 2026.2.14 | Feb 14 | 50+ security hardening fixes, faster test suite, file boundary parity [1] |
| 2026.2.15 | Feb 16 | Discord Components v2, plugin hooks, vLLM onboarding, TUI fixes, memory self-heal [14] |

The velocity is extreme — multiple major releases per week, each with dozens of security fixes. This signals both rapid maturity and an actively-shifting attack surface.

### 1.4 Ecosystem and Community

- **ClawHub**: Skill marketplace (npm-based). Subject to supply-chain attacks — SlowMist documented a malicious-skill poisoning campaign ("ClawHavoc") [7].
- **USDC OpenClaw Hackathon**: 200+ submissions, 1,800+ votes, $30K prizes. Blockchain/crypto integration is an active community interest [7].
- **ClawGlasses**: Vision-grounding hardware project — physical glasses feeding camera input to OpenClaw agents for real-world autonomy [9].
- **NanoClaw**: Security-first competitor using per-agent container isolation as a core primitive [19].
- **ClawSec**: Community security skill suite for drift detection, audit automation, and skill integrity verification [13].

---

## 2. Capabilities — Including Esoteric Use Cases

### 2.1 Core Agent Capabilities

| Capability | Description |
|-----------|-------------|
| **Tool execution** | Shell commands, file read/write/edit, apply patches, process management |
| **Browser automation** | Full CDP (Chrome DevTools Protocol) control — navigate, click, type, screenshot |
| **Multi-model routing** | Opus 4.6, GPT-5.3-Codex, xAI Grok, Baidu Qianfan, vLLM, OpenAI Codex OAuth |
| **Sandbox isolation** | Per-agent or per-session ephemeral Docker containers with `capDrop=["ALL"]`, `network=none` |
| **Memory** | QMD vector index with LanceDB, Voyage AI embeddings, auto-capture with injection filtering |
| **Security audit** | Built-in `openclaw security audit --deep --fix` with policy drift detection |
| **Self-update** | Can update itself when asked [6] |
| **Cron/scheduled tasks** | Built-in cron system for autonomous background operations |
| **Session management** | Per-channel, per-peer, or global session scoping with transcript archival |
| **Token usage tracking** | Built-in token usage dashboard (since 2026.2.6) |

### 2.2 Channel Integrations

| Channel | Features |
|---------|----------|
| **Discord** | Components v2 (buttons, selects, modals), exec approval UX, forum/media threads (2026.2.15) |
| **WhatsApp** | DM pairing, group mention gating, media handling |
| **Telegram** | Bot token auth, DM policy, group allowlists |
| **Slack** | OAuth, channel routing |
| **Signal** | Auto-install via Homebrew, arm64 support (2026.2.15) |
| **Web UI** | Gateway Control UI with device pairing, session management |
| **TUI** | Terminal UI with `--session` support, ANSI sanitization (2026.2.15) |

### 2.3 Advanced and Esoteric Use Cases

These are the unusual, boundary-pushing things people are doing with OpenClaw in 2026:

1. **Self-updating agent**: OpenClaw can update its own binary when asked. Ryan Carson demonstrated this: "Just asked OpenClaw to update itself... 'Done. Updated from 2026.2.1 -> 2026.2.2-3. Restarting now'" [6].

2. **Physical-world grounding via ClawGlasses**: Camera-equipped glasses feed visual input to OpenClaw, enabling agents to "see" and act in the physical world — the argument being that the biggest leap for autonomous agents isn't scaling LLMs but grounding them in physical reality [9].

3. **Blockchain/DeFi automation**: The USDC hackathon demonstrated OpenClaw agents executing on-chain transactions, managing wallets, and automating DeFi strategies [7].

4. **iOS alpha node onboarding** (2026.2.9): Phone-as-node — mobile devices joining the agent mesh for device pairing, phone control plugins, and on-the-go agent interaction.

5. **Multi-node mesh (Clawnet)**: The Clawnet protocol refactor is unifying all clients (Mac app, CLI, iOS, Android, headless nodes) under one authenticated protocol with TLS pinning, stable IDs, and scoped roles [17].

6. **LLM-as-a-judge for skill safety**: The skill code safety scanner (2026.2.6) uses an LLM to evaluate skill code before execution [2].

7. **Prompt injection as persistent attack**: Attackers inject instructions into SOUL.md memory files that persist across sessions and restarts — turning the agent's own memory against it [12].

8. **Agent-to-agent communication**: `sessions_spawn` and `sessions_send` tools allow agents to spawn child sessions and send messages to other agents, creating multi-agent workflows.

9. **Exec approval forwarding**: Discord's exec approval UX lets agents request human approval for dangerous commands through interactive buttons in Discord channels (2026.2.15).

10. **vLLM self-hosted model support**: Onboarding now supports vLLM as a first-class provider with model discovery (2026.2.15), enabling fully self-hosted LLM inference without any external API calls.

---

## 3. Security Landscape

### 3.1 CVEs and GHSAs

The security research community has been aggressive with OpenClaw. As of February 2026, **73 security advisories** have been published, with AISLE researchers alone responsible for 15 of them [8].

| Advisory | Severity | Description |
|----------|----------|-------------|
| **CVE-2026-25253 / GHSA-g8p2-7wf7-98mq** | Critical | Token exfiltration via WebSocket handling — stolen gateway token enables RCE [8] |
| **GHSA-943q-mwmv-hhvh** | High | Gateway HTTP `/tools/invoke` endpoint allows unauthorized tool execution (referenced in our README) |
| **GHSA-q284-4pvr-m585** | High | OS command injection via SSH project root path — unescaped path in `sshNodeCommand` [11] |
| **GHSA-r8g4-86fx-92mq** | High | Local file inclusion — agents read sensitive files via crafted paths [8] |
| **GHSA-g55j-c2v4-pjcg** | High | Command injection through unescaped user input and unsafe WebSocket config writes [8] |
| **GHSA-pchc-86f6-8758** | High | Unauthorized agent pipeline access — chat participants trigger agent without authorization [8] |

**Belgium CCB issued a national advisory** warning of a critical 1-click RCE vulnerability requiring immediate patching [11].

### 3.2 Prompt Injection as Attack Vector

Prompt injection against OpenClaw is not a theoretical concern — it's the primary threat model. Key attack patterns documented in 2026:

1. **Persistent memory manipulation**: Injecting instructions into SOUL.md/memory files that survive restarts [12].
2. **Transcript compaction replay**: Malicious web content embeds instructions that persist through context window compaction (mitigated in 2026.2.12+) [12].
3. **Tool hijacking**: Tricking the agent into executing tools on the attacker's behalf [12].
4. **Silent skill installation**: Malicious skills execute `npm install` with lifecycle scripts, performing network calls and prompt injection without user awareness [13].

OpenClaw 2026.2.15 added defenses: recalled memories are now treated as untrusted context with explicit non-instruction framing, and likely prompt-injection payloads are skipped during auto-capture [14].

### 3.3 Supply Chain — ClawHub Skills Poisoning

SlowMist documented the "ClawHavoc" campaign: **341+ malicious skills** published to ClawHub that:
- Execute lifecycle scripts during `npm install`
- Perform silent network calls (exfiltration)
- Inject prompts to bypass safety guidelines
- Modify SOUL.md to persist across sessions

Mitigation: OpenClaw 2026.2.15 now installs plugin/hook dependencies with `--ignore-scripts` [14]. The skill code safety scanner (2026.2.6) provides LLM-based pre-execution analysis [2].

### 3.4 Third-Party Security Tools

| Tool | Purpose |
|------|---------|
| **ClawSec** [13] | Security skill suite — drift detection, audit automation, skill integrity verification |
| **openclaw-secure-stack** [20] | One-command secure deployment with skills scanner and prompt injection protection |
| **Composio controls** [20] | Managed auth routing so agents never handle raw tokens |
| **LiteLLM proxy** [19] | Model gateway with request filtering, rate limiting, cost controls, centralized logging |

---

## 4. Issues in the Current Deployment Plan

### 4.1 Critical Issues

#### C1: Auth mode uses deprecated `gateway.password` instead of `gateway.auth.token`

**Location**: README Step 10.3

The plan uses:
```bash
openclaw config set gateway.password "$(cat /tmp/.gw-pass)"
```

Official docs [15] recommend token-based auth as the primary mode:
```bash
openclaw config set gateway.auth.mode "token"
openclaw config set gateway.auth.token "$(cat /tmp/.gw-pass)"
```

Token auth uses `Authorization: Bearer <token>` headers, which are more appropriate for programmatic/proxy access than password auth. The `gateway.password` key may map to the older auth path that doesn't enforce `gateway.auth.mode`.

**Risk**: If `gateway.auth.mode` defaults to something unexpected (e.g., `"trusted-proxy"` when the gateway is behind a reverse proxy), the password may not be enforced at all.

#### C2: Tailscale auth not explicitly disabled behind reverse proxy

**Location**: README Step 10.3 (missing)

The official security docs [15] state:

> "Disable `allowTailscale` if you terminate TLS in front of the Gateway. Use token/password auth or Trusted Proxy Auth instead."

Behind a reverse proxy, an attacker who can reach the internal network could spoof `tailscale-user-login` headers. The plan does not set:
```bash
openclaw config set gateway.auth.allowTailscale false
```

**Risk**: Auth bypass via header spoofing on the internal network.

#### C3: mDNS/Bonjour discovery not disabled

**Location**: README Step 10.3 (missing)

OpenClaw broadcasts its presence via mDNS (`_openclaw-gw._tcp`) by default. On a Docker bridge network, this leaks service metadata (role, port, transport) to any container on the network.

The plan should add:
```bash
openclaw config set discovery.mdns.mode "off"
```

Or set `OPENCLAW_DISABLE_BONJOUR=1` in the service environment.

**Risk**: Information disclosure. In `"full"` mode, also leaks filesystem paths and SSH port.

### 4.2 High-Severity Issues

#### H1: Squid ACL source ranges too broad

**Location**: README Step 9 — `squid.conf`

```
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
```

These ranges cover ~17.9 million and ~1 million addresses respectively. The actual Docker bridge subnet is typically a /24 or /16. The plan's own comment says "Tighten these to your actual bridge subnet" but provides the broad ranges as the working default.

**Risk**: Any container on any RFC 1918 network that can reach the Squid proxy can use it as an egress gateway to whitelisted LLM APIs.

#### H2: Browser control not explicitly disabled

**Location**: README Step 10.3 (missing)

OpenClaw's browser control feature (`gateway.nodes.browser`) defaults to `"off"` but should be explicitly set in a hardened deployment:
```bash
openclaw config set gateway.nodes.browser.mode "off"
```

If accidentally enabled, agents gain full CDP access to a browser profile — including all logged-in sessions, cookies, and local storage.

**Risk**: If enabled by drift or misconfiguration, complete browser profile compromise.

#### H3: Control UI security not configured

**Location**: README Step 10.3 (missing)

The plan doesn't explicitly set:
```bash
openclaw config set gateway.controlUi.allowInsecureAuth false
openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth false
```

These default to `false`, but defense-in-depth requires explicit configuration — especially since the gateway is bound to `0.0.0.0` (see H4).

**Risk**: If defaults change in a future version, the Control UI could accept insecure auth or skip device identity.

#### H4: Gateway bound to `0.0.0.0` — broader than necessary

**Location**: README Step 10.3

```bash
openclaw config set gateway.bind "0.0.0.0"
```

The official docs [15] recommend: "Prefer Tailscale Serve over LAN binds; never expose unauthenticated on `0.0.0.0`."

Behind a reverse proxy, the gateway only needs to be reachable on the internal bridge network. While password auth is configured, binding to all interfaces exposes the gateway to any network the container is attached to.

**Recommendation**: Use `"lan"` or `"custom"` bind mode targeting the bridge subnet, or document why `0.0.0.0` is required for reverse proxy routing.

#### H5: Logging redaction not configured

**Location**: README Step 10.3 (missing)

The plan doesn't set `logging.redactSensitive`, which controls whether tool output, URLs, and error messages are redacted in logs. The default is `"tools"` but should be explicitly configured:
```bash
openclaw config set logging.redactSensitive "tools"
```

Session transcripts are stored as plaintext JSONL at `~/.openclaw/agents/<agentId>/sessions/*.jsonl`. If the data volume is compromised, unredacted transcripts leak tool arguments, URLs, and potentially API keys.

#### H6: No skill/plugin installation policy

**Location**: README (missing entirely)

Given the ClawHavoc supply-chain attack (341+ malicious skills on ClawHub), the plan should:
1. Set an explicit plugin allowlist: `openclaw config set plugins.allow '[]'`
2. Document a policy for evaluating and approving skills before installation
3. Reference the skill code safety scanner added in 2026.2.6

**Risk**: An operator installs a malicious skill that exfiltrates credentials or modifies SOUL.md.

### 4.3 Medium-Severity Issues

#### M1: Session isolation not configured

**Location**: README Step 10.3 (missing)

The plan doesn't configure `session.dmScope`. In a multi-user deployment (multiple people messaging the agent via channels), the default `"main"` mode shares a single session across all senders — leaking context between users.

Should set:
```bash
openclaw config set session.dmScope "per-channel-peer"
```

#### M2: No `maxTokens` clamping or model configuration

**Location**: README Step 10.3 (missing)

OpenClaw 2026.2.15 added `maxTokens` clamping to `contextWindow` to prevent invalid model configs. The plan doesn't configure any model-specific settings, token limits, or model routing — relying entirely on defaults.

For a production deployment, explicit model configuration prevents runaway costs and ensures the strongest models (which are more injection-resistant) are used for tool-enabled agents.

#### M3: Password rotation script uses potentially wrong config key

**Location**: README Step 12 — `rotate-password.sh`

```bash
openclaw config set gateway.password "$(cat /tmp/.gw-pass)"
```

This should be `gateway.auth.password` or `gateway.auth.token` depending on the auth mode. See issue C1.

#### M4: Docker socket proxy version not verified as latest

**Location**: README Step 7

`tecnativa/docker-socket-proxy:0.6.0` is pinned. The latest version should be verified — if a security fix was released post-0.6.0, the plan deploys a vulnerable proxy with direct Docker socket access.

#### M5: No webhook/OpenResponses endpoint security

**Location**: README (missing)

OpenClaw exposes HTTP endpoints including `/tools/invoke` (the GHSA-943q-mwmv-hhvh attack surface) and potentially OpenResponses API endpoints. The plan configures `gateway.tools.deny` for `/tools/invoke` but doesn't address:
- Rate limiting on HTTP endpoints
- OpenResponses API enablement/disablement
- URL allowlists for file/image responses

### 4.4 Low-Severity Issues

#### L1: `NODE_ENV=production` may not be recognized

**Location**: README Step 8

`NODE_ENV: production` is a Node.js convention. OpenClaw's Go-based gateway may not use this variable. Verify whether OpenClaw respects `NODE_ENV` or uses its own production mode flag.

#### L2: No explicit `group debug output` suppression

**Location**: README Step 10.3 (missing)

If channels are configured later, verbose/reasoning output in groups can leak internal context:
```bash
openclaw config set agents.defaults.groupChat.enableReasoning false
openclaw config set agents.defaults.groupChat.enableVerbose false
```

#### L3: Force-update order in Step 10.1

**Location**: README Step 10.1

The force-update order is: docker-proxy → openclaw → openclaw-egress. But `openclaw` depends on `openclaw-egress` for outbound connectivity (`HTTP_PROXY`). If `openclaw` restarts before `openclaw-egress` is ready, the gateway may fail health checks while trying to reach LLM APIs. Safer order: docker-proxy → openclaw-egress → openclaw.

#### L4: Healthcheck only on `openclaw`, not on other services

**Location**: README Step 10.1

Only the `openclaw` service has a healthcheck (`openclaw doctor --quiet`). Neither `docker-proxy` nor `openclaw-egress` have healthchecks. Squid supports health verification via `squidclient mgr:info`, and the socket proxy can be probed via `/_ping`.

#### L5: Cron log duplication

**Location**: README Step 12

The maintenance script writes to its own timestamped log file *and* cron redirects to `maintenance-cron.log`. This creates duplicate logging — the cron redirect captures only stdout/stderr that escapes `tee`, not the full log.

---

## 5. Missing Features

### 5.1 Security Features Not Configured

| Feature | What It Does | Why It Matters |
|---------|-------------|----------------|
| **`gateway.auth.mode: "token"`** | Token-based auth (recommended) | More secure than password for programmatic access |
| **`gateway.auth.allowTailscale: false`** | Disable Tailscale header auth | Prevents header spoofing behind reverse proxy |
| **`discovery.mdns.mode: "off"`** | Disable mDNS broadcast | Prevents service metadata leakage |
| **`gateway.nodes.browser.mode: "off"`** | Disable browser control | Prevents CDP-based browser profile access |
| **`gateway.controlUi.*`** | Control UI security settings | Prevent insecure auth downgrades |
| **`logging.redactSensitive: "tools"`** | Redact sensitive data in logs | Protect tool arguments and URLs in transcripts |
| **`session.dmScope: "per-channel-peer"`** | Session isolation | Prevent cross-user context leakage |
| **`plugins.allow: []`** | Plugin allowlist | Block unauthorized skill installation |
| **Gateway TLS (`gateway.tls`)** | End-to-end encryption | Currently relies on reverse proxy for TLS; no encryption between reverse proxy and gateway |

### 5.2 Operational Features Missing

| Feature | Description | Impact |
|---------|-------------|--------|
| **Observability stack** | No Prometheus, Grafana, Loki, or structured logging integration | No visibility into gateway health, token usage, error rates, or security events |
| **Alerting** | No alerting for service failures, security audit drift, or cost thresholds | Failures discovered only during manual checks or user reports |
| **Token usage / cost monitoring** | OpenClaw has a built-in token dashboard (since 2026.2.6) — not configured | No cost visibility or runaway-spend protection |
| **LiteLLM or model proxy** | No centralized model gateway | No request filtering, rate limiting, or cost controls at the model layer |
| **Structured JSON logging** | No `logging.file` or JSON output configuration | Log aggregation requires parsing unstructured text |
| **Backup encryption** | Backups stored as plaintext `.tar.gz` | Compromised backup host exposes all OpenClaw data including credentials |

### 5.3 Platform Capabilities Not Leveraged

| Capability | Description | Relevance |
|-----------|-------------|-----------|
| **Channel integrations** | WhatsApp, Discord, Telegram, Slack, Signal | The plan deploys the gateway but configures zero channels — the agent can't receive messages |
| **Memory/RAG system** | QMD indexing, Voyage AI embeddings, auto-capture | No memory configuration — agents have no persistent knowledge |
| **Cron/heartbeat** | Autonomous scheduled tasks | Not configured — agents are purely reactive |
| **Multi-agent routing** | Different agents for different channels/contexts | Single default agent with no routing rules |
| **Exec approval workflow** | Human-in-the-loop for dangerous commands | Not configured (requires channel integration) |
| **Device/node pairing** | iOS alpha, mobile nodes, Clawnet mesh | Not addressed |
| **vLLM self-hosted inference** | Local model serving without external API calls | Not configured despite being supported since 2026.2.15 |
| **SOUL.md / system prompt** | Agent personality and security guidelines | Not created — the official security docs recommend including specific security instructions in the agent prompt |

---

## 6. Alternative Architectures Worth Considering

### Podman Rootless Deployment

OpenClaw officially supports Podman [18] with rootless containers via `setup-podman.sh`. Key security advantages over the current Docker-based plan:

- **No root daemon**: Podman runs daemonless. Container escape lands as unprivileged user, not root.
- **User namespace isolation**: UID 0 inside container maps to unprivileged UID on host.
- **Quadlet/systemd integration**: Production-grade service management without Docker daemon.
- **Reduced blast radius**: Compromise limited to `openclaw` user's home directory.

**Trade-off**: A Podman deployment would mean replacing Docker Compose with direct systemd/Quadlet orchestration.

### NanoClaw

NanoClaw [19] is a security-first alternative that uses per-agent Linux containers (Apple Container on macOS, Docker on Linux). Each agent runs in its own isolated environment with a separate filesystem. Bash commands execute within the container, not on the host. A compromised agent can only access explicitly shared directories.

**Relevance**: If security is the paramount concern, NanoClaw's architecture provides stronger isolation guarantees by design.

### LiteLLM Model Gateway

Instead of OpenClaw talking directly to LLM providers through the Squid egress proxy, a LiteLLM instance [19] between OpenClaw and the providers would add:
- Request filtering and content moderation
- Per-model rate limiting and cost controls
- Centralized API key management (keys never touch OpenClaw)
- Audit logging of all model interactions
- Fallback routing between providers

---

## 7. Recommendations Summary

Ordered by priority:

| # | Action | Severity | Effort |
|---|--------|----------|--------|
| 1 | Switch to `gateway.auth.mode: "token"` with `gateway.auth.token` | Critical | Low |
| 2 | Disable Tailscale auth: `gateway.auth.allowTailscale: false` | Critical | Low |
| 3 | Disable mDNS: `discovery.mdns.mode: "off"` | Critical | Low |
| 4 | Tighten Squid ACLs to actual bridge subnet | High | Low |
| 5 | Disable browser control: `gateway.nodes.browser.mode: "off"` | High | Low |
| 6 | Configure logging redaction: `logging.redactSensitive: "tools"` | High | Low |
| 7 | Set plugin allowlist: `plugins.allow: []` | High | Low |
| 8 | Add Control UI security settings | High | Low |
| 9 | Configure session isolation: `session.dmScope` | Medium | Low |
| 10 | Fix service force-update order (egress before gateway) | Low | Low |
| 11 | Add healthchecks for docker-proxy and openclaw-egress | Low | Medium |
| 12 | Add observability stack (Loki + Grafana minimum) | Medium | High |
| 13 | Add LiteLLM model proxy for cost control and key isolation | Medium | High |
| 14 | Configure at least one channel integration | — | Medium |
| 15 | Create SOUL.md with security guidelines | High | Low |
| 16 | Evaluate Podman rootless as Docker alternative | — | High |

---

## Sources

1. [OpenClaw 2026.2.14 announcement (X.com)](https://x.com/openclaw/status/2022880208664301599)
2. [OpenClaw v2026.2.6 announcement (X.com)](https://x.com/openclaw/status/2020059808444084506)
3. [David Hendrickson on OpenClaw Feb 1 update (X.com)](https://x.com/TeksEdge/status/2018358790253670421)
4. [Aaron Levie on OpenAI hiring OpenClaw creator (X.com)](https://x.com/levie/status/2023152367366222151)
5. [The Daily Tech Feed on OpenClaw v2026.2.6 (X.com)](https://x.com/dailytechonx/status/2020524528862920773)
6. [Ryan Carson — OpenClaw self-update (X.com)](https://x.com/ryancarson/status/2019059775573540981)
7. [Grey Ledger — USDC OpenClaw Hackathon + ClawHub supply chain (X.com)](https://x.com/Airdrops_one/status/2021717739233313029)
8. [TechNadu — 15 OpenClaw Vulnerabilities Found and Fixed](https://www.technadu.com/15-openclaw-security-flaws-disclosed-as-ai-agent-platform-sees-rapid-enterprise-adoption/620374/)
9. [ClawGlasses — OpenClaw Vision for True Autonomy (X.com)](https://x.com/ClawGlasses/status/2019562617199817062)
10. [Mark Gadala-Maria on OpenAI acquiring OpenClaw (X.com)](https://x.com/markgadala/status/2023176503077318797)
11. [Belgium CCB — Critical OpenClaw RCE vulnerability advisory](https://ccb.belgium.be/advisories/warning-critical-vulnerability-openclaw-allows-1-click-remote-code-execution-when)
12. [Penligent — The OpenClaw Prompt Injection Problem](https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/)
13. [ClawSec — Security skill suite (GitHub)](https://github.com/prompt-security/clawsec)
14. [OpenClaw 2026.2.15 release (GitHub)](https://github.com/openclaw/openclaw/releases/tag/v2026.2.15)
15. [OpenClaw Security Documentation](https://docs.openclaw.ai/gateway/security)
16. [GBHackers — OpenClaw 2026.2.12 patches 40+ vulnerabilities](https://gbhackers.com/openclaw-2026-2-12-released/)
17. [Clawnet refactor — protocol + auth unification](https://openclawcn.com/en/docs/refactor/clawnet/)
18. [OpenClaw Podman installation docs](https://docs.openclaw.ai/install/podman)
19. [NanoClaw — Container-isolated AI agents (TrendingTopics)](https://www.trendingtopics.eu/nanoclaw-challenges-openclaw-with-container-isolated-ai-agents-for-enhanced-security/)
20. [Composio — Secure OpenClaw setup guide](https://composio.dev/blog/secure-openclaw-moltbot-clawdbot-setup)
21. [Cisco Blogs — Personal AI Agents like OpenClaw Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare)
22. [Giskard — OpenClaw security issues include data leakage & prompt injection](https://www.giskard.ai/knowledge/openclaw-security-vulnerabilities-include-data-leakage-and-prompt-injection-risks)
23. [Jamf — OpenClaw AI Agent Insider Threat Analysis](https://www.jamf.com/blog/openclaw-ai-agent-insider-threat-analysis/)
24. [Leo Ye — The OpenClaw Ecosystem 2026 (X.com)](https://x.com/LeoYe_AI/status/2021903008741929410)
25. [HAProxy — Properly securing OpenClaw with authentication](https://www.haproxy.com/blog/properly-securing-openclaw-with-authentication)
26. [OpenClaw CHANGELOG.md (GitHub)](https://github.com/openclaw/openclaw/blob/main/CHANGELOG.md)
27. [OpenClaw Architecture overview — Paolo Perazzo](https://ppaolo.substack.com/p/openclaw-system-architecture-overview)
28. [Markaicode — Secure OpenClaw Web UI with SSL](https://markaicode.com/openclaw-ssl-setup-guide/)
