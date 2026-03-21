# Troubleshooting

> Common issues and their solutions for clincher deployments.

---

## Symptom/Diagnostic/Fix Reference

| Symptom | Diagnostic | Fix |
|---------|-----------|-----|
| Sandbox fails | `docker logs openclaw-docker-proxy` | Verify EXEC=1, check socket proxy is reachable on `openclaw-net` |
| Gateway unreachable | `docker compose logs openclaw` | Confirm `gateway.bind "lan"`, check `trustedProxies` includes `proxy-net` subnet |
| Gateway auth rejected | `docker exec openclaw openclaw config get gateway.auth.mode` | Re-run Step 5 auth section; verify `Authorization: Bearer <token>` header |
| Agents can't reach LLM APIs | `docker exec openclaw wget -qO- http://openclaw-litellm:4000/health/liveliness` | Verify LiteLLM is healthy, check `agents.defaults.apiBase` points to `http://openclaw-litellm:4000`, check `ANTHROPIC_API_KEY` in `/opt/openclaw/.env` |
| LiteLLM can't reach providers | `docker exec openclaw-litellm curl -x http://openclaw-egress:4750 -I https://api.anthropic.com` | Check `smokescreen-acl.yaml` whitelist, verify `HTTP_PROXY` env var |
| Memory index fails | `docker exec openclaw openclaw memory index --verify` | Verify Voyage AI key, check `*.voyageai.com` in `smokescreen-acl.yaml` |
| Telegram crashes / drops messages | `docker compose logs openclaw --tail 100 \| grep -i telegram` | Check channel token and pairing status. If upgrading from 2026.2.17, the streaming race condition was fixed in 2026.2.19 — remove legacy `streamMode "off"` if present |
| Channel not connecting | `docker exec openclaw openclaw doctor` | Check channel token, verify `dmPolicy`, check pairing status |
| Container keeps restarting | `docker compose logs <service> --tail 100` | Check resource limits (`docker stats`), verify config files are readable |
| Egress proxy blocks legitimate traffic | `docker logs openclaw-egress` | Check `smokescreen-acl.yaml` allowed_domains, verify domain glob pattern matches (e.g., `*.anthropic.com`) |
| Container OOM-killed | `dmesg \| grep -i oom`, `docker inspect <container> --format '{{.State.OOMKilled}}'` | Check `docker stats` — verify the OOM'd container's memory limit. On 64 GB host, individual container limits are the constraint, not total host memory. Increase the specific container's limit or reduce concurrent sandbox count |
| High swap usage | `free -h`, `vmstat 1 5` | If swap > 1 GB consistently, reduce `agents.defaults.sandbox.docker.memoryLimit` or lower openclaw memory limit to 3G |
| Config error after update | `docker exec openclaw openclaw doctor --repair` | Restore from backup: `docker exec openclaw cp /root/.openclaw/config.json.bak /root/.openclaw/config.json` and restart. See Step 5 backup note |
| Redis unreachable / LiteLLM cache errors | `docker exec openclaw-redis redis-cli ping`, `docker logs openclaw-litellm --tail 50 \| grep -i redis` | Verify redis container is healthy, check `REDIS_HOST` env var in LiteLLM, verify both are on `openclaw-net`. LiteLLM falls back to no-cache if Redis is unavailable — service continues, just without caching |
| Low cache hit rate | `docker exec openclaw-redis redis-cli dbsize`, check Prometheus `litellm_cache_hit_metric_total` on monitoring VPS | Normal for first 24 hours. If persistently < 5%, lower `similarity_threshold` from 0.8 to 0.7 in `litellm-config.yaml` and restart LiteLLM |

## Quick Diagnostic Commands

```bash
# Overall service health
docker compose ps

# Full security audit
docker exec $(docker ps -q -f "name=openclaw") openclaw security audit --deep

# Doctor check (covers channels, config, connectivity)
docker exec openclaw openclaw doctor

# Sandbox status
docker exec $(docker ps -q -f "name=openclaw") openclaw sandbox explain

# Resource usage across all containers
docker stats --no-stream

# Check egress proxy connectivity
docker exec $(docker ps -q -f "name=openclaw") \
  curl -x http://openclaw-egress:4750 -I https://api.anthropic.com

# View recent logs for a specific service
docker compose logs <service> --tail 100
```

---

For full deployment and configuration details, see the [deployment guide](../README.md).
