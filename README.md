# 🦞 OpenClaw Hardened Swarm Deployment (2026.2)

**Production-grade, least-privilege OpenClaw deployment on CapRover Docker Swarm.**
All sensitive services pinned to a single trusted node (`nyc`).

## Key Information
- **Target**: 4-node Ubuntu 24.04 Swarm (3 managers + 1 worker) with leader on `nyc`
- **OpenClaw Version**: `openclaw/openclaw:2026.2.15` (pinned)
- **Threat Model**: Prompt injection → arbitrary tool execution → host/container escape

> **Important — CapRover `captainVersion: 4` Parser Limitation**
>
> CapRover's built-in compose parser only applies: `image`, `environment`, `ports`, `volumes`, `depends_on`, and `hostname`. All `deploy` block settings (placement constraints, resource limits, restart policies, healthchecks) are **silently ignored**. The YAML examples below include `deploy` blocks for documentation purposes, but you **must** apply them via CapRover's **Service Update Override** feature (see [Step 10.1](#step-101-apply-caprover-service-update-overrides)).

## Table of Contents

- [Step 1: Prerequisites](#step-1-prerequisites)
- [Step 2: Initialize Swarm on nyc Leader](#step-2-initialize-swarm-on-nyc-leader)
- [Step 3: Label the Trusted Node](#step-3-label-the-trusted-node)
- [Step 4: Join Additional Manager Nodes](#step-4-join-additional-manager-nodes)
- [Step 5: Set Up NFS Shared Storage](#step-5-set-up-nfs-shared-storage-caprover-dashboard-ha)
- [Step 6: Configure Firewall](#step-6-configure-firewall-run-on-all-nodes)
- [Step 7: Deploy Docker Socket Proxy](#step-7-deploy-docker-socket-proxy)
- [Step 8: Deploy OpenClaw Gateway](#step-8-deploy-openclaw-gateway-primary-service)
- [Step 9: Deploy Egress Proxy (Squid)](#step-9-deploy-egress-proxy-squid)
- [Step 10: Post-Deployment Configuration](#step-10-post-deployment-configuration)
- [Step 11: Verification](#step-11-verification)
- [Step 12: Maintenance](#step-12-maintenance)
- [Step 13: Troubleshooting](#step-13-troubleshooting)
- [Step 14: Automated Periodic Checks](#step-14-automated-periodic-checks)

---

### Step 1: Prerequisites

#### 1.1 UFW + ufw-docker Setup (Run on **ALL** Nodes)

> **WARNING**: The firewall rule below only allows SSH from localhost (127.0.0.1). If you are connected via remote SSH, you **will be locked out** when UFW is enabled. Either replace `127.0.0.1` with your admin IP, or ensure you have out-of-band console/IPMI/KVM access before running `ufw --force enable`. Step 6 will reset and reconfigure the firewall with your admin IP on port 9922.

```bash
# 1. Install UFW
sudo apt update
sudo apt install ufw -y

# 2. Install ufw-docker
sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
sudo chmod +x /usr/local/bin/ufw-docker

# 3. Initial configuration (ufw-docker is installed in Step 6 after full reset)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 127.0.0.1 to any port 22 proto tcp   # temporary local SSH
sudo ufw --force enable
```

#### 1.2 Static Admin IP + Cloudflare Setup

**Static Admin IP (SSH Access)**
- Use a dedicated **static public IP** for admin access.
- Record this IP as `$ADMIN_IP` (you will use it in Step 6).

**Cloudflare Setup (Recommended)**
1. Add your domain to Cloudflare and update nameservers.
2. Create an **A** or **CNAME** record pointing to `nyc` node's public IP with **Proxied** status.
3. Set SSL/TLS to **Full (strict)**.
4. Enable WAF + Bot Fight Mode.
5. Strongly consider **Cloudflare Tunnel** for maximum security.

**Other prerequisites**:
- Healthy 4-node Ubuntu 24.04 servers
- CapRover already installed

### Step 2: Initialize Swarm on nyc Leader

**Run only on the `nyc` node**:

```bash
# Initialize Swarm (use the node's public or internal IP)
docker swarm init --advertise-addr <NYC_NODE_IP>

# Example:
# docker swarm init --advertise-addr 10.0.0.10
```

Save the manager join token shown in the output:

```bash
docker swarm join-token manager
```

#### Create Encrypted Overlay Network

Create a dedicated encrypted overlay network for OpenClaw services. This encrypts all inter-service traffic (IPSEC) and isolates OpenClaw from other Swarm services.

```bash
docker network create --driver overlay --opt encrypted openclaw-net
```

> **Note**: Do not use `--attachable` — that would allow standalone (`docker run`) containers to join this network, weakening isolation.

### Step 3: Label the Trusted Node
```bash
docker node update --label-add openclaw.trusted=true nyc
```

### Step 4: Join Additional Manager Nodes

On the other two nodes:

```bash
docker swarm join --token <MANAGER_TOKEN_FROM_NYC> <NYC_LEADER_IP>:2377
```

Verify:
```bash
docker node ls
```

### Step 5: Set Up NFS Shared Storage (CapRover Dashboard HA)

**NFS Server (recommended: nyc)**:
```bash
apt install nfs-kernel-server -y
mkdir -p /captain/data && chown nobody:nogroup /captain/data

# Restrict to your Swarm subnet (replace with your actual CIDR).
# no_root_squash is required because CapRover's captain container runs as root
# and needs root-level filesystem control over its data directory.
echo "/captain/data <SWARM_SUBNET_CIDR>(rw,sync,no_subtree_check,no_root_squash)" > /etc/exports
# Example: /captain/data 10.0.0.0/24(rw,sync,no_subtree_check,no_root_squash)

exportfs -ra && systemctl restart nfs-kernel-server
```

**NFS Clients (all managers)**:
```bash
apt install nfs-common -y
mkdir -p /captain/data
mount -o nosuid <NFS_SERVER_IP>:/captain/data /captain/data
echo "<NFS_SERVER_IP>:/captain/data /captain/data nfs defaults,nosuid 0 0" >> /etc/fstab
mount -a
```

Migrate existing CapRover data, update volume binding in CapRover dashboard, then scale captain service back up.

### Step 6: Configure Firewall (Run on All Nodes)

```bash
ADMIN_IP="YOUR_STATIC_IP"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow from $ADMIN_IP to any port 9922 proto tcp
ufw limit 9922/tcp
```

#### Cloudflare Ingress Setup
```bash
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
  ufw allow from $ip to any port 80,443 proto tcp
done

for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
  ufw allow from $ip to any port 80,443 proto tcp
done
```

#### Swarm Inter-node Rules
```bash
# Replace with space-separated IPs of all swarm nodes
# Example: for ip in 10.0.0.10 10.0.0.11 10.0.0.12 10.0.0.13; do
for ip in <ALL_NODE_IPS>; do
  ufw allow from $ip to any port 2377,7946 proto tcp
  ufw allow from $ip to any port 7946,4789 proto udp
done

ufw-docker install --confirm-license
systemctl restart docker
ufw --force enable
```

### Step 7: Deploy Docker Socket Proxy
**App Name**: `docker-proxy`

> **Security note**: `EXEC: "1"` is required because OpenClaw's sandbox system uses `docker exec` to run tools inside sandbox containers. `BUILD` is intentionally disabled — OpenClaw does not need to build images at runtime, and enabling it would allow construction of images with host filesystem mounts.

```yaml
captainVersion: 4
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:0.6.0
    environment:
      CONTAINERS: "1"
      IMAGES: "1"
      INFO: "1"
      VERSION: "1"
      PING: "1"
      EVENTS: "1"
      EXEC: "1"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    # NOTE: deploy block is for documentation only — CapRover ignores it.
    # Apply via Service Update Override (Step 10.1).
    deploy:
      placement:
        constraints:
          - node.labels.openclaw.trusted == true
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
```

### Step 8: Deploy OpenClaw Gateway (Primary Service)
**App Name**: `openclaw`

```yaml
captainVersion: 4
services:
  openclaw:
    image: openclaw/openclaw:2026.2.15
    environment:
      DOCKER_HOST: tcp://srv-captain--docker-proxy:2375
      NODE_ENV: production
      HTTP_PROXY: http://srv-captain--openclaw-egress:3128
      HTTPS_PROXY: http://srv-captain--openclaw-egress:3128
      NO_PROXY: srv-captain--docker-proxy,localhost,127.0.0.1
    volumes:
      - openclaw-data:/root/.openclaw
    # NOTE: deploy block is for documentation only — CapRover ignores it.
    # Apply via Service Update Override (Step 10.1).
    deploy:
      placement:
        constraints:
          - node.labels.openclaw.trusted == true
      resources:
        limits:
          cpus: "2.0"
          memory: 6G
      restart_policy:
        condition: on-failure
```

### Step 9: Deploy Egress Proxy (Squid)
**App Name**: `openclaw-egress`

First, create the Squid config file on the `nyc` node:
```bash
mkdir -p /opt/openclaw-config
cat > /opt/openclaw-config/squid.conf << 'EOF'
http_port 3128

# Only allow port 443 (HTTPS)
acl Safe_ports port 443
http_access deny !Safe_ports

# Whitelist LLM provider API domains (add your providers here)
acl llm_apis dstdomain .anthropic.com
acl llm_apis dstdomain .openai.com
# acl llm_apis dstdomain .api.groq.com
# acl llm_apis dstdomain .googleapis.com

# Only allow HTTPS CONNECT to whitelisted domains (no plain HTTP)
acl CONNECT method CONNECT
http_access allow CONNECT llm_apis

# Deny everything else
http_access deny all
EOF
```

Then deploy via CapRover:
```yaml
captainVersion: 4
services:
  openclaw-egress:
    image: ubuntu/squid:6.10-24.04_beta
    volumes:
      - /opt/openclaw-config/squid.conf:/etc/squid/squid.conf:ro
    # NOTE: deploy block is for documentation only — CapRover ignores it.
    # Apply via Service Update Override (Step 10.1).
    deploy:
      placement:
        constraints:
          - node.labels.openclaw.trusted == true
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
```

### Step 10: Post-Deployment Configuration

#### Step 10.1: Apply CapRover Service Update Overrides

CapRover's `captainVersion: 4` parser ignores `deploy` blocks. You must apply placement constraints, resource limits, restart policies, and healthchecks via the **Service Update Override** in the CapRover dashboard (App Config → Service Update Override) for each app.

**`docker-proxy` Service Update Override**:
```json
{
  "TaskTemplate": {
    "Placement": {
      "Constraints": ["node.labels.openclaw.trusted == true"]
    },
    "Resources": {
      "Limits": {
        "MemoryBytes": 536870912,
        "NanoCPUs": 500000000
      }
    }
  },
  "Networks": [
    { "Target": "openclaw-net" }
  ]
}
```

**`openclaw` Service Update Override**:
```json
{
  "TaskTemplate": {
    "ContainerSpec": {
      "Healthcheck": {
        "Test": ["CMD", "openclaw", "doctor", "--quiet"],
        "Interval": 30000000000,
        "Timeout": 10000000000,
        "Retries": 3
      }
    },
    "Placement": {
      "Constraints": ["node.labels.openclaw.trusted == true"]
    },
    "Resources": {
      "Limits": {
        "MemoryBytes": 6442450944,
        "NanoCPUs": 2000000000
      }
    },
    "RestartPolicy": {
      "Condition": "on-failure"
    }
  },
  "Networks": [
    { "Target": "openclaw-net" }
  ]
}
```

**`openclaw-egress` Service Update Override**:
```json
{
  "TaskTemplate": {
    "Placement": {
      "Constraints": ["node.labels.openclaw.trusted == true"]
    },
    "Resources": {
      "Limits": {
        "MemoryBytes": 536870912,
        "NanoCPUs": 500000000
      }
    }
  },
  "Networks": [
    { "Target": "openclaw-net" }
  ]
}
```

After applying overrides, force-update each service:
```bash
docker service update --force srv-captain--docker-proxy
docker service update --force srv-captain--openclaw
docker service update --force srv-captain--openclaw-egress
```

Verify constraints and network are applied:
```bash
docker service inspect srv-captain--openclaw --format '{{json .Spec.TaskTemplate.Placement}}'
docker service inspect srv-captain--docker-proxy --format '{{json .Spec.TaskTemplate.Placement}}'
docker service inspect srv-captain--openclaw-egress --format '{{json .Spec.TaskTemplate.Placement}}'
docker service inspect srv-captain--openclaw --format '{{json .Spec.TaskTemplate.Networks}}'
```

#### Step 10.2: Provision API Keys

OpenClaw needs LLM provider API keys to function. Provision them inside the container:

```bash
docker exec -it $(docker ps -q -f "name=srv-captain--openclaw\.") sh

# Create .env file for API keys
cat > /root/.openclaw/.env << 'ENVEOF'
ANTHROPIC_API_KEY=sk-ant-your-key-here
# OPENAI_API_KEY=sk-your-key-here
# Add other provider keys as needed
ENVEOF

chmod 600 /root/.openclaw/.env
exit
```

> **Alternative (recommended)**: Use Docker Swarm secrets for API key injection:
> ```bash
> echo "sk-ant-your-key-here" | docker secret create anthropic_api_key -
> ```
> Then reference the secret in the service configuration via Service Update Override.

#### Step 10.3: Gateway and Sandbox Hardening

Generate the gateway password on the host (where `openssl` is available), then apply all hardening config inside the container:

```bash
# Generate password on the host
GW_PASSWORD=$(openssl rand -hex 32)
echo "Save this gateway password: $GW_PASSWORD"

# Apply hardening inside the container
docker exec -it $(docker ps -q -f "name=srv-captain--openclaw\.") sh
```

Inside the container shell:
```bash
# Gateway — bind to all interfaces since CapRover's nginx reverse proxy
# connects via the overlay network, not loopback.
# trustedProxies should include CapRover's nginx (captain) service.
openclaw config set gateway.bind "0.0.0.0"
openclaw config set gateway.trustedProxies '["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]'
openclaw config set gateway.password "<PASTE_GW_PASSWORD_HERE>"

# Sandbox isolation
openclaw config set agents.defaults.sandbox.mode "all"
openclaw config set agents.defaults.sandbox.scope "agent"
openclaw config set agents.defaults.sandbox.workspaceAccess "none"
openclaw config set agents.defaults.sandbox.docker.network "none"
openclaw config set agents.defaults.sandbox.docker.capDrop '["ALL"]'

# Agent-level tool denials (comprehensive list for 2026.2.x)
openclaw config set agents.defaults.tools.deny '["process", "browser", "nodes", "gateway", "sessions_spawn", "sessions_send", "elevated", "host_exec", "docker", "camera", "canvas", "cron"]'

# Gateway HTTP /tools/invoke endpoint denials (separate attack surface — GHSA-943q-mwmv-hhvh)
openclaw config set gateway.tools.deny '["sessions_spawn", "sessions_send", "gateway", "elevated", "host_exec", "docker", "camera", "canvas", "cron"]'

# Channel policies
openclaw config set channels.*.dmPolicy "pairing"
openclaw config set channels.*.groups.*.requireMention true

# File permissions
chmod 700 /root/.openclaw
find /root/.openclaw -type f -exec chmod 600 {} \;

# Verify
openclaw security audit --deep --fix
openclaw doctor
openclaw sandbox explain

exit
```

Back on the host:
```bash
docker service update --force srv-captain--openclaw
```

### Step 11: Verification
```bash
# Inside the OpenClaw container
docker exec $(docker ps -q -f "name=srv-captain--openclaw\.") openclaw security audit --deep
docker exec $(docker ps -q -f "name=srv-captain--openclaw\.") openclaw sandbox explain

# Verify placement constraints are actually applied
docker service inspect srv-captain--openclaw --format '{{json .Spec.TaskTemplate.Placement}}'
docker service inspect srv-captain--docker-proxy --format '{{json .Spec.TaskTemplate.Placement}}'
docker service inspect srv-captain--openclaw-egress --format '{{json .Spec.TaskTemplate.Placement}}'

# Verify resource limits
docker service inspect srv-captain--openclaw --format '{{json .Spec.TaskTemplate.Resources}}'

# Verify services are on the trusted node
docker node ps nyc

# Verify egress proxy is working (should succeed for whitelisted domains)
docker exec $(docker ps -q -f "name=srv-captain--openclaw\.") \
  curl -x http://srv-captain--openclaw-egress:3128 -I https://api.anthropic.com

# Verify gateway is reachable through CapRover
curl -I https://openclaw.yourdomain.com
```

### Step 12: Maintenance
(Place scripts in `/opt/openclaw-monitoring/` on `nyc`)

```bash
mkdir -p /opt/openclaw-monitoring/{logs,backups}
```

**Main Maintenance Script** (`openclaw-maintenance.sh`):
```bash
#!/bin/bash
set -euo pipefail
LOG="/opt/openclaw-monitoring/logs/maintenance-$(date +%F-%H%M).log"
OC_CONTAINER() { docker ps -q -f "name=srv-captain--openclaw\."; }

echo "=== OpenClaw Maintenance Run - $(date) ===" | tee -a "$LOG"

# Backup OpenClaw data
tar -czf /opt/openclaw-monitoring/backups/openclaw-data-$(date +%F).tar.gz \
  -C /var/lib/docker/volumes/openclaw-data/_data . 2>> "$LOG"

# Security audit (before force-update, while container is stable)
docker exec $(OC_CONTAINER) openclaw security audit --deep --fix >> "$LOG" 2>&1

# Force-update to pinned image (catches config drift)
docker service update --force --image openclaw/openclaw:2026.2.15 srv-captain--openclaw >> "$LOG" 2>&1

# Wait for new container to be running after force-update
echo "Waiting for new container to stabilize..." >> "$LOG"
sleep 30
RETRIES=0
while [ -z "$(OC_CONTAINER)" ] && [ $RETRIES -lt 12 ]; do
  sleep 5
  RETRIES=$((RETRIES + 1))
done

# Health check (against the new container)
docker exec $(OC_CONTAINER) openclaw doctor >> "$LOG" 2>&1

# Prune old backups (keep 14 days)
find /opt/openclaw-monitoring/backups -name "*.tar.gz" -mtime +14 -delete

# Prune old logs (keep 30 days)
find /opt/openclaw-monitoring/logs -name "*.log" -mtime +30 -delete

echo "=== Maintenance Complete ===" | tee -a "$LOG"
```

**Password Rotation Script** (`rotate-password.sh`):
```bash
#!/bin/bash
set -euo pipefail
LOG="/opt/openclaw-monitoring/logs/password-rotation-$(date +%F).log"
OC_CONTAINER() { docker ps -q -f "name=srv-captain--openclaw\."; }

echo "=== Password Rotation - $(date) ===" | tee -a "$LOG"

NEW_PASSWORD=$(openssl rand -hex 32)
docker exec $(OC_CONTAINER) \
  openclaw config set gateway.password "$NEW_PASSWORD" >> "$LOG" 2>&1

docker service update --force srv-captain--openclaw >> "$LOG" 2>&1

echo "Password rotated successfully. Update any clients with the new password." | tee -a "$LOG"
echo "=== Rotation Complete ===" | tee -a "$LOG"
```

**Cron Schedule** (add to `nyc` node):
```bash
# Weekly maintenance (Sunday 3 AM)
0 3 * * 0 /opt/openclaw-monitoring/openclaw-maintenance.sh

# Monthly password rotation (1st of month, 4 AM)
0 4 1 * * /opt/openclaw-monitoring/rotate-password.sh
```

### Step 13: Troubleshooting

| Symptom | Diagnostic | Fix |
|---------|-----------|-----|
| Sandbox fails | Check `docker-proxy` logs: `docker service logs srv-captain--docker-proxy` | Verify EXEC=1 is set, socket proxy is reachable |
| Gateway unreachable | Verify bind address + trustedProxies include CapRover's overlay IP range | Set `gateway.bind "0.0.0.0"` and expand `trustedProxies` |
| Constraint issues | `docker node inspect nyc --format '{{json .Spec.Labels}}'` | Verify label exists, check Service Update Override is applied |
| Agents can't reach LLM APIs | `docker exec $(docker ps -q -f "name=srv-captain--openclaw\.") curl -x http://srv-captain--openclaw-egress:3128 https://api.anthropic.com` | Check squid.conf whitelist, verify HTTP_PROXY env var |
| Service not on trusted node | `docker service ps srv-captain--openclaw` | Re-apply Service Update Override constraints |
| Failed update | `docker service rollback srv-captain--openclaw` | Rollback to previous service spec, then investigate |

### Step 14: Automated Periodic Checks

Create directory:
```bash
mkdir -p /opt/openclaw-monitoring/logs
```

Then create the daily, weekly, and constraint check scripts (same as previous versions) and add them to cron.

---

**Done.** Deploy services in order (Steps 1-9), apply Service Update Overrides and hardening (Step 10), verify (Step 11), then set up monitoring (Steps 12-14).

**Next recommended actions**:
1. Start with Step 1 on all nodes
2. Initialize Swarm on `nyc` (Step 2)
3. Deploy services in order (Steps 7-9)
4. Apply Service Update Overrides (Step 10.1) — **critical, do not skip**
5. Provision API keys (Step 10.2)
6. Apply hardening (Step 10.3)
7. Verify everything (Step 11)
8. Set up monitoring scripts (Steps 12, 14)
