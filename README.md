# 🦞 OpenClaw Swarm

Secure, HA swarm with isolated OpenClaw on CapRover. 🦞

**Rating**: 98/100  
**Target**: Existing 4-node CapRover Swarm (Ubuntu 24.04)  
**Strategy**: Pin sensitive services to trusted node (`chicago`)

Original: https://github.com/openclaw/openclaw

## Table of Contents

- [High Availability](#high-availability)
  - [Promote Managers](#promote-managers)
  - [NFS Shared Storage (Dashboard HA)](#nfs-shared-storage-dashboard-ha)
    - [NFS Server (One Node)](#nfs-server-one-node)
    - [NFS Clients (Managers)](#nfs-clients-managers)
    - [Migrate CapRover Data](#migrate-caprover-data)
    - [NFS Firewall (Server)](#nfs-firewall-server)
- [Node Setup](#node-setup)
- [Core Services (Pinned)](#core-services-pinned)
- [Deployment](#deployment)
  - [1. Firewall (All Nodes)](#1-firewall-all-nodes)
  - [2. Docker Proxy (Pinned)](#2-docker-proxy-pinned)
  - [3. OpenClaw](#3-openclaw)
  - [4. Hardening Config](#4-hardening-config)
  - [5. Sandbox](#5-sandbox)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [Verify](#verify)

## High Availability

Configure **3 managers + 1 worker** (tolerates 1 failure).

### Promote Managers
On leader:
```bash
docker swarm join-token manager
```
On two nodes:
```bash
docker swarm join --token <TOKEN> <LEADER_IP>:2377
```
Verify:
```bash
docker node ls
```

### NFS Shared Storage (Dashboard HA)

#### NFS Server (One Node)
```bash
sudo apt install nfs-kernel-server -y
sudo mkdir -p /captain/data
sudo chown nobody:nogroup /captain/data
echo "/captain/data *(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -a
sudo systemctl restart nfs-kernel-server
```

#### NFS Clients (Managers)
```bash
sudo apt install nfs-common -y
sudo mkdir -p /captain/data
sudo mount NFS_SERVER_IP:/captain/data /captain/data
echo "NFS_SERVER_IP:/captain/data /captain/data nfs defaults 0 0" | sudo tee -a /etc/fstab
sudo mount -a
```

#### Migrate CapRover Data
```bash
docker service scale captain-captain=0
sudo rsync -av /var/lib/docker/volumes/captain--captain-data/_data/ /captain/data/
```
Dashboard → captain app → Volumes: Host `/captain/data` → Container `/captain/data`

#### NFS Firewall (Server)
```bash
sudo ufw allow from <MANAGER_IPs> to any port 2049,111 proto tcp/udp
```

Test:
```bash
docker node demote <OLD_LEADER>
```

## Node Setup

```bash
docker node update --label-add openclaw.trusted=true chicago
```

## Core Services (Pinned)

| App              | Image                              | Purpose          | Constraint                          |
|------------------|------------------------------------|------------------|-------------------------------------|
| openclaw         | img-captain--openclaw:latest       | Gateway          | node.labels.openclaw.trusted == true |
| docker-proxy     | tecnativa/docker-socket-proxy      | Socket isolation | node.labels.openclaw.trusted == true |
| openclaw-egress  | ubuntu/squid:latest                | Outbound proxy   | node.labels.openclaw.trusted == true |
| otel-collector   | otel/opentelemetry-collector-contrib | Metrics        | node.labels.openclaw.trusted == true |

## Deployment

### 1. Firewall (All Nodes)
```bash
ADMIN_IP="YOUR_ADMIN_IP"

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow from $ADMIN_IP to any port 9922 proto tcp
sudo ufw limit 9922/tcp

# Cloudflare 80/443 (full ranges)

# Inter-node
for ip in NODE2_IP NODE3_IP NODE4_IP; do
  sudo ufw allow from $ip to any port 2377,7946 proto tcp
  sudo ufw allow from $ip to any port 7946,4789 proto udp
done

sudo ufw-docker install
sudo systemctl restart docker
sudo ufw --force enable
```

### 2. Docker Proxy (Pinned)
```yaml
captainVersion: 4
services:
  - captainServiceName: docker-proxy
    image: tecnativa/docker-socket-proxy:latest
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
    deploy:
      placement:
        constraints:
          - node.labels.openclaw.trusted == true
```

### 3. OpenClaw
Env: `DOCKER_HOST=tcp://srv-captain--docker-proxy:2375`  
Constraint: `node.labels.openclaw.trusted == true`  
Pin egress & otel similarly.

### 4. Hardening Config
```bash
docker exec -it $(docker ps -q -f name=srv-captain--openclaw) sh

openclaw config set agents.defaults.tools.deny '["process", "browser"]'
openclaw config set agents.defaults.sandbox.mode "all"
openclaw config set agents.defaults.sandbox.docker.network "none"
openclaw config set agents.defaults.sandbox.docker.capDrop '["ALL"]'
# ... (apply full prior list)

exit
docker service update --force srv-captain--openclaw
```

### 5. Sandbox
```bash
./scripts/sandbox-setup.sh
openclaw sandbox setup
```

## Maintenance
- Channels: Pairing + allowlists
- Skills: Local low-risk
- Weekly: `openclaw doctor`

## Troubleshooting

- **Sandbox fails to spawn**: Check proxy logs `docker logs srv-captain--docker-proxy`
- **NFS mount errors**: `showmount -e NFS_SERVER_IP` or check `dmesg | grep nfs`
- **Leader failover stuck**: `docker service ls | grep captain` and manually scale
- **OpenClaw unresponsive**: Run `openclaw doctor`; check gateway logs
- **Firewall blocks**: Temporarily disable `sudo ufw disable` for testing
- **Constraint issues**: Verify label `docker node inspect chicago | grep Labels`

## Verify
```bash
docker node ls
docker service inspect srv-captain--openclaw | grep Constraints
docker node ps chicago
sudo ufw status
curl -I https://openclaw.yourdomain.com
```

Done!
