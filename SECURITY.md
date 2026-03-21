# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |

## Reporting a Vulnerability

Email **security@droxey.com** with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (which layer of the security model is affected)

We aim to respond within 48 hours and patch critical issues within 7 days.

**Do not** open a public GitHub issue for security vulnerabilities.

## Security Model

Clincher implements a 9-layer defense-in-depth architecture for hardened AI agent deployment:

1. **Network isolation** — `openclaw-net` is `internal: true` (no direct internet)
2. **Egress control** — Smokescreen whitelists only HTTPS to LLM provider domains
3. **Socket proxy** — EXEC/CONTAINERS/IMAGES/INFO only; BUILD/SECRETS/SWARM denied
4. **Container hardening** — `cap_drop: ["ALL"]`, `no-new-privileges` at daemon + container level
5. **Sandbox isolation** — `capDrop=["ALL"]`, `network=none`, no workspace access
6. **Tool denials** — 13 dangerous tools blocked at agent and gateway levels
7. **Credential handling** — File-based secret passing; never CLI args
8. **SSH hardening** — Non-standard port, key-only auth, deploy user only
9. **Firewall** — UFW + fail2ban, admin IP whitelist, Cloudflare-only ingress

See the [full deployment guide](docs/deployment-guide.md) for implementation details.
