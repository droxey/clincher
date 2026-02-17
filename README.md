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

---

### Step 1: Prerequisites

#### 1.1 UFW + ufw-docker Setup (Run on **ALL** Nodes)

> **WARNING**: The firewall rule below only allows SSH from localhost (127.0.0.1). If you are connected via remote SSH, you **will be locked out** when UFW is enabled. Either replace `127.0.0.1` with your admin IP, or ensure you have out-of-band console/IPMI/KVM access before running `ufw --force enable`. Step 6 will reset and reconfigure the firewall with your admin IP on port 9922.

```bash
# 1. Install UFW
sudo apt update
sudo apt install ufw -y

# 2. Install ufw-docker (verify checksum after download)
sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
# Verify the download before making it executable:
#   sha256sum /usr/local/bin/ufw-docker
# Compare against the known hash from the ufw-docker releases page.
# Only proceed if the hash matches.
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
mount -o nosuid,noexec,nodev <NFS_SERVER_IP>:/captain/data /captain/data
echo "<NFS_SERVER_IP>:/captain/data /captain/data nfs defaults,nosuid,noexec,nodev 0 0" >> /etc/fstab
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

> **Security note**: These IPs are fetched over HTTPS, but you should verify them against
> [Cloudflare's published IP ranges](https://www.cloudflare.com/ips/) before applying.
> Consider pinning the expected CIDRs in a local file for reproducible, auditable firewall rules.

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
  # NFS (restrict to Swarm nodes only — required for CapRover HA in Step 5)
  ufw allow from $ip to any port 2049,111 proto tcp
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
      # Explicitly deny sensitive APIs (defense-in-depth — defaults are 0)
      BUILD: "0"
      COMMIT: "0"
      CONFIGS: "0"
      DISTRIBUTION: "0"
      NETWORKS: "0"
      NODES: "0"
      PLUGINS: "0"
      SECRETS: "0"
      SERVICES: "0"
      SESSION: "0"
      SWARM: "0"
      SYSTEM: "0"
      TASKS: "0"
      VOLUMES: "0"
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
    # networks is also ignored by CapRover — applied via override.
    networks:
      - captain-overlay-network
      - openclaw-net
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
    networks:
      - captain-overlay-network
      - openclaw-net
```

### Step 9: Deploy Egress Proxy (Squid)
**App Name**: `openclaw-egress`

First, create the Squid config file on the `nyc` node:
```bash
mkdir -p /opt/openclaw-config
cat > /opt/openclaw-config/squid.conf << 'EOF'
http_port 3128

# Only allow HTTPS port (443)
acl Safe_ports port 443
http_access deny !Safe_ports

# Restrict client source to Docker overlay networks
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
http_access deny !localnet

# Whitelist LLM provider API domains (add your providers here)
acl llm_apis dstdomain .anthropic.com
acl llm_apis dstdomain .openai.com
# acl llm_apis dstdomain .api.groq.com
# acl llm_apis dstdomain .googleapis.com

# CONNECT tunneling (used for all HTTPS requests through the proxy)
acl CONNECT method CONNECT
http_access deny CONNECT !llm_apis
http_access allow CONNECT llm_apis

# Allow plain HTTP(S) forwarding to whitelisted domains only
http_access allow llm_apis

# Deny everything else
http_access deny all

# Hardening
via off
forwarded_for delete
httpd_suppress_version_string on
EOF
```

Then deploy via CapRover:
```yaml
captainVersion: 4
services:
  openclaw-egress:
    image: ubuntu/squid:6.6-24.04_edge
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
    networks:
      - captain-overlay-network
      - openclaw-net
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
    { "Target": "captain-overlay-network" },
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
    { "Target": "captain-overlay-network" },
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
    { "Target": "captain-overlay-network" },
    { "Target": "openclaw-net" }
  ]
}
```

> **Important**: Both `captain-overlay-network` (for CapRover service discovery via `srv-captain--<name>`) and `openclaw-net` (for encrypted inter-service traffic) are required. If either network is missing, services cannot communicate. After applying, verify:
> ```bash
> docker service inspect srv-captain--openclaw --format '{{json .Spec.TaskTemplate.Networks}}'
> ```
> Output should list both network targets.

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

OpenClaw needs LLM provider API keys to function. Use Docker Swarm secrets (recommended) to avoid leaking keys to the process table or shell history.

**Recommended: Docker Swarm secrets**
```bash
# Create secrets from files (not CLI args) to avoid process-table exposure.
# Write each key to a temporary file, then pipe it in:
touch /tmp/anthropic_key && chmod 600 /tmp/anthropic_key
nano /tmp/anthropic_key   # paste your key, save, exit
docker secret create anthropic_api_key /tmp/anthropic_key
shred -u /tmp/anthropic_key

# Repeat for other providers as needed
```
Then reference the secret in the service configuration via Service Update Override.

**Alternative (less secure)**: Provision keys directly inside the container.
Note that `docker exec` commands expose arguments in the process table — use an interactive shell:
```bash
docker exec -it $(docker ps -q -f "name=srv-captain--openclaw\.") sh

# Create .env file for API keys (type/paste — do not pass keys as CLI args)
nano /root/.openclaw/.env
# Add: ANTHROPIC_API_KEY=sk-ant-your-key-here
# Add: OPENAI_API_KEY=sk-your-key-here (if needed)

chmod 600 /root/.openclaw/.env
exit
```

#### Step 10.3: Gateway and Sandbox Hardening

Generate the gateway password on the host (where `openssl` is available), then apply all hardening config inside the container:

```bash
# Ensure monitoring directory exists (also created in Step 12 — safe to run twice)
mkdir -p /opt/openclaw-monitoring/{logs,backups}
chmod 700 /opt/openclaw-monitoring /opt/openclaw-monitoring/logs /opt/openclaw-monitoring/backups

# Generate password on the host and save to a secured file (not stdout)
openssl rand -hex 32 > /opt/openclaw-monitoring/.gateway-password
chmod 600 /opt/openclaw-monitoring/.gateway-password
echo "Gateway password saved to /opt/openclaw-monitoring/.gateway-password"

# Copy the password file into the container (avoids process-table exposure)
docker cp /opt/openclaw-monitoring/.gateway-password \
  $(docker ps -q -f "name=srv-captain--openclaw\."):/tmp/.gw-pass

# Apply hardening inside the container
docker exec -it $(docker ps -q -f "name=srv-captain--openclaw\.") sh
```

Inside the container shell:
```bash
# Gateway — bind to all interfaces since CapRover's nginx reverse proxy
# connects via the overlay network, not loopback.
openclaw config set gateway.bind "0.0.0.0"

# trustedProxies: Replace <OVERLAY_SUBNET> with your actual Docker overlay subnet.
# Find it with: docker network inspect captain-overlay-network --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
# Example: if the subnet is 10.0.1.0/24, use that instead of the broad /8 range.
openclaw config set gateway.trustedProxies '["127.0.0.1", "<OVERLAY_SUBNET>"]'
# Fallback if you cannot determine the exact subnet (less secure — trusts all RFC 1918):
# openclaw config set gateway.trustedProxies '["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]'

# Set password from file (avoids leaking to process table via CLI args)
openclaw config set gateway.password "$(cat /tmp/.gw-pass)"
rm -f /tmp/.gw-pass

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
chmod 700 /opt/openclaw-monitoring /opt/openclaw-monitoring/logs /opt/openclaw-monitoring/backups
```

**Main Maintenance Script** (`openclaw-maintenance.sh`):
```bash
#!/bin/bash
set -euo pipefail
LOG="/opt/openclaw-monitoring/logs/maintenance-$(date +%F-%H%M).log"
OC_CONTAINER() { docker ps -q -f "name=srv-captain--openclaw\."; }

(
  flock -n 200 || { echo "Another maintenance run is already in progress"; exit 1; }

  echo "=== OpenClaw Maintenance Run - $(date) ===" | tee -a "$LOG"

  # Backup OpenClaw data via a temporary container (avoids relying on Docker internals)
  docker run --rm \
    -v openclaw-data:/source:ro \
    -v /opt/openclaw-monitoring/backups:/backup \
    alpine:3.21 tar -czf "/backup/openclaw-data-$(date +%F).tar.gz" -C /source . 2>> "$LOG"

  # Security audit (before force-update, while container is stable)
  CID=$(OC_CONTAINER)
  if [ -n "$CID" ]; then
    docker exec "$CID" openclaw security audit --deep --fix >> "$LOG" 2>&1
  else
    echo "WARNING: Container not running, skipping pre-update audit" >> "$LOG"
  fi

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

  if [ -z "$(OC_CONTAINER)" ]; then
    echo "ERROR: Container did not stabilize after 90s" | tee -a "$LOG"
    # Continue to cleanup even on failure
  else
    # Health check (against the new container)
    docker exec "$(OC_CONTAINER)" openclaw doctor >> "$LOG" 2>&1
  fi

  # Prune old backups (keep 14 days)
  find /opt/openclaw-monitoring/backups -name "*.tar.gz" -mtime +14 -delete

  # Prune old logs (keep 30 days)
  find /opt/openclaw-monitoring/logs -name "*.log" -mtime +30 -delete

  echo "=== Maintenance Complete ===" | tee -a "$LOG"

) 200>/opt/openclaw-monitoring/.maintenance.lock
```

**Password Rotation Script** (`rotate-password.sh`):
```bash
#!/bin/bash
set -euo pipefail
LOG="/opt/openclaw-monitoring/logs/password-rotation-$(date +%F).log"
PASS_FILE="/opt/openclaw-monitoring/.gateway-password"
OC_CONTAINER() { docker ps -q -f "name=srv-captain--openclaw\."; }

(
  flock -n 200 || { echo "Another rotation is already running"; exit 1; }

  echo "=== Password Rotation - $(date) ===" | tee -a "$LOG"

  # Generate new password to file (never as a CLI argument)
  openssl rand -hex 32 > "${PASS_FILE}.new"
  chmod 600 "${PASS_FILE}.new"

  # Copy into container and set from file to avoid process-table leak
  CONTAINER_ID=$(OC_CONTAINER)
  docker cp "${PASS_FILE}.new" "${CONTAINER_ID}:/tmp/.gw-pass"
  docker exec "$CONTAINER_ID" \
    sh -c 'openclaw config set gateway.password "$(cat /tmp/.gw-pass)" && rm -f /tmp/.gw-pass' >> "$LOG" 2>&1

  # Persist password file on host (rotate backup)
  mv "${PASS_FILE}.new" "$PASS_FILE"

  docker service update --force srv-captain--openclaw >> "$LOG" 2>&1

  echo "Password rotated. New password saved to $PASS_FILE" | tee -a "$LOG"
  echo "=== Rotation Complete ===" | tee -a "$LOG"

) 200>/opt/openclaw-monitoring/.rotate-password.lock
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

---

**Done.** Deploy services in order (Steps 1-9), apply Service Update Overrides and hardening (Step 10), verify (Step 11), then set up monitoring (Steps 12-13).

**Next recommended actions**:
1. Start with Step 1 on all nodes
2. Initialize Swarm on `nyc` (Step 2)
3. Deploy services in order (Steps 7-9)
4. Apply Service Update Overrides (Step 10.1) — **critical, do not skip**
5. Provision API keys (Step 10.2)
6. Apply hardening (Step 10.3)
7. Verify everything (Step 11)
8. Set up monitoring scripts (Step 12)
