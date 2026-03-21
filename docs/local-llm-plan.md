# Local LLM Hosting Plan for OpenClaw

> **Date**: 2026-03-21
> **Status**: Draft — awaiting approval
> **Goal**: Reduce cloud API costs by routing routine agent tasks to free, locally hosted or rented GPU models

---

## Current State

| Component | Value |
|-----------|-------|
| Server CPU | AMD EPYC Milan, 48 cores (single socket) |
| RAM | 64 GB DDR4 |
| Storage | 4 TB NVMe |
| GPU | None (planning vast.ai integration) |
| LLM Proxy | LiteLLM v1.81.3 at `openclaw-litellm:4000` |
| Concurrency | 8+ simultaneous OpenClaw agents |
| Current models | Anthropic Claude, OpenAI GPT, Groq Llama, xAI Grok, Google Gemini (all cloud) |

---

## Recommended Architecture: Three-Tier Inference

```
┌─────────────────────────────────────────────────────────────┐
│                     LiteLLM Proxy (:4000)                   │
│              usage-based-routing-v2 + fallback               │
├──────────────┬──────────────────────┬───────────────────────┤
│  Tier 1      │  Tier 2              │  Tier 3               │
│  LOCAL CPU   │  VAST.AI GPU         │  CLOUD API            │
│  (Ollama)    │  (vLLM)              │  (Anthropic, etc.)    │
│              │                      │                       │
│  8B-14B      │  30B-70B             │  Claude Opus/Sonnet   │
│  quantized   │  full/quantized      │  GPT-5.2, Grok-4     │
│              │                      │                       │
│  Free        │  ~$0.10-0.30/hr GPU  │  Per-token pricing    │
│  ~10 t/s     │  ~50-200 t/s         │  ~80-150 t/s          │
│  Simple tasks│  Complex reasoning   │  Hardest tasks        │
└──────────────┴──────────────────────┴───────────────────────┘
```

**Routing logic**: LiteLLM tries Tier 1 first. If the local model is overloaded or the task exceeds a complexity threshold, it falls back to Tier 2 (vast.ai), then Tier 3 (cloud).

---

## Tier 1: Local CPU Inference (Ollama)

### Why Ollama

- One-command setup, bundles llama.cpp, OpenAI-compatible API
- LiteLLM already supports `ollama/` prefix — zero client changes
- Runs in Docker alongside existing stack on `openclaw-net`
- Handles 1-4 concurrent requests well; tunable to 8 with `OLLAMA_NUM_PARALLEL`

### Recommended Models (Q4_K_M Quantization)

| Model | Size (Q4) | Expected Speed (48-core EPYC) | Best For |
|-------|-----------|-------------------------------|----------|
| **Qwen3 8B** | ~5 GB | 10-15 t/s | General chat, summarization, classification |
| **Gemma 3 12B** | ~7 GB | 6-10 t/s | Multilingual, longer context, better reasoning |
| **Phi-4-mini 3.8B** | ~2.5 GB | 15-25 t/s | Code completion, quick Q&A (fastest option) |
| **Llama 3.3 8B** | ~5 GB | 8-12 t/s | Tool calling, structured output, coding |

**Recommendation**: Start with **Qwen3 8B** (best all-around) and **Phi-4-mini** (fast code tasks). Load both — Ollama hot-swaps models in ~2 seconds with 64 GB RAM.

### Performance Optimization for EPYC Milan

Memory bandwidth is the bottleneck, not core count:

1. Verify all memory channels are populated (`sudo dmidecode -t memory | grep -c "Size: [0-9]"`)
2. Disable SMT for inference threads — hurts performance on EPYC
3. Pin Ollama to a single NUMA node: `numactl --cpunodebind=0 --membind=0 ollama serve`
4. Set `OLLAMA_NUM_PARALLEL=4` (start conservative, tune up)
5. Use `OLLAMA_FLASH_ATTENTION=1` for reduced memory usage

### Docker Compose Addition

```yaml
  ollama:
    image: ollama/ollama:latest
    container_name: openclaw-ollama
    volumes:
      - ollama-data:/root/.ollama
    environment:
      OLLAMA_NUM_PARALLEL: "4"
      OLLAMA_FLASH_ATTENTION: "1"
      OLLAMA_HOST: "0.0.0.0:11434"
    networks:
      - openclaw-net
    deploy:
      resources:
        limits:
          cpus: "32"
          memory: "48G"
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:11434/api/tags || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

volumes:
  ollama-data:
```

### LiteLLM Config Addition

```yaml
# Add to model_list in litellm-config.yaml.j2
- model_name: "ollama/qwen3-8b"
  litellm_params:
    model: "ollama/qwen3:8b"
    api_base: "http://openclaw-ollama:11434"
  model_info:
    max_budget: 0          # Free — no budget needed
  rpm: 30

- model_name: "ollama/phi4-mini"
  litellm_params:
    model: "ollama/phi4-mini"
    api_base: "http://openclaw-ollama:11434"
  model_info:
    max_budget: 0
  rpm: 60
```

---

## Tier 2: Vast.ai GPU Inference (vLLM)

### Why Vast.ai + vLLM

- GPU rental at ~$0.10-0.30/hr (vs $2-4/hr on AWS/GCP)
- vLLM's PagedAttention handles 8+ concurrent requests with predictable latency
- OpenAI-compatible API — LiteLLM treats it like any other provider
- Vast.ai has a [native LiteLLM integration guide](https://vast.ai/article/hybrid-ai-inference-local-litellm-proxy-with-remote-vast-ai-gpu)

### Recommended Models for Vast.ai

| Model | GPU Requirement | Vast.ai Cost (est.) | Best For |
|-------|----------------|---------------------|----------|
| **Llama 3.3 70B (AWQ)** | 1× A100 80GB or 2× RTX 4090 | ~$0.50-0.80/hr | Complex reasoning, tool use, coding |
| **Qwen3.5 30B** | 1× RTX 4090 24GB (Q4) | ~$0.15-0.25/hr | Mid-range reasoning, cost-effective |
| **DeepSeek-R1-Distill-70B** | 1× A100 80GB | ~$0.50-0.80/hr | Math, science, deep reasoning |
| **MiMo-V2-Flash (15B active)** | 1× RTX 4090 24GB | ~$0.15-0.25/hr | Fast agentic workflows |

**Recommendation**: Start with **Qwen3.5 30B** on a single RTX 4090 (~$0.20/hr) for the best cost-to-quality ratio. Scale to 70B on A100 when needed.

### Deployment on Vast.ai

```bash
# Search for affordable instances
vastai search offers 'gpu_name=RTX_4090 num_gpus=1 reliability>0.98 dph<0.30'

# Deploy vLLM with your chosen model
vastai create instance <INSTANCE_ID> \
  --image vllm/vllm-openai:latest \
  --env '-p 8000:8000' \
  --disk 100 \
  --onstart-cmd "vllm serve Qwen/Qwen3.5-30B-AWQ \
    --port 8000 \
    --max-model-len 8192 \
    --gpu-memory-utilization 0.92 \
    --quantization awq"
```

### LiteLLM Config for Vast.ai

```yaml
# Add to model_list — replace <VAST_IP>:<PORT> with actual endpoint
- model_name: "vastai/qwen3.5-30b"
  litellm_params:
    model: "openai/Qwen/Qwen3.5-30B-AWQ"
    api_base: "http://<VAST_IP>:<PORT>/v1"
    api_key: "dummy"                       # vLLM default — no auth
  model_info:
    max_budget: 50
  rpm: 120
```

### Security Considerations

- Vast.ai instances are **not on your internal network** — route through Smokescreen egress proxy
- Add vast.ai instance IPs to the egress whitelist (or use a WireGuard tunnel)
- vLLM has **no built-in auth** — use an API key via `--api-key` flag or a WireGuard tunnel
- Never send sensitive prompts to shared GPU instances without encryption in transit

---

## Tier 3: Cloud Fallback (Existing)

Your current cloud providers remain the fallback for:

- Tasks requiring the strongest models (Claude Opus, GPT-5.2)
- When local/vast.ai models are down or overloaded
- Injection-resistant tasks requiring frontier-grade instruction following

No changes needed — LiteLLM's `usage-based-routing-v2` already handles failover.

---

## Fallback Chain Configuration

```yaml
# router_settings in litellm-config.yaml.j2
router_settings:
  routing_strategy: "usage-based-routing-v2"
  num_retries: 2
  retry_after: 5
  fallbacks:
    # If local model fails, try vast.ai, then cloud
    - ollama/qwen3-8b: ["vastai/qwen3.5-30b", "groq/llama-3.3-70b-versatile"]
    - ollama/phi4-mini: ["vastai/qwen3.5-30b", "anthropic/claude-haiku-4-5-20251001"]
    - vastai/qwen3.5-30b: ["anthropic/claude-sonnet-4-20250514"]
```

---

## Cost Analysis (Estimated Monthly)

### Current State (All Cloud)

| Provider | Est. Monthly Cost |
|----------|-------------------|
| Anthropic (Opus primary) | $200-800 |
| Groq (fast tasks) | $5-50 |
| Other providers | $20-100 |
| **Total** | **$225-950/mo** |

### With Local + Vast.ai Hybrid

| Tier | Est. Monthly Cost | Traffic Share |
|------|-------------------|---------------|
| Tier 1: Ollama (free) | $0 | 40-60% of requests |
| Tier 2: Vast.ai (~$0.20/hr, 8hr/day) | $50-150 | 20-30% of requests |
| Tier 3: Cloud (complex only) | $50-200 | 10-30% of requests |
| **Total** | **$50-350/mo** | 100% |

**Estimated savings: 50-70%** depending on workload distribution.

---

## Implementation Phases

### Phase 1: Local Ollama (Week 1)

1. Add Ollama container to Docker Compose
2. Pull Qwen3 8B and Phi-4-mini models
3. Add models to LiteLLM config with fallback chains
4. Test with OpenClaw agents on simple tasks
5. Monitor token throughput and latency

### Phase 2: Vast.ai Integration (Week 2-3)

1. Create vast.ai account, test instance provisioning
2. Deploy vLLM with Qwen3.5 30B on RTX 4090
3. Configure LiteLLM to route to vast.ai endpoint
4. Set up WireGuard tunnel or API key auth
5. Add Smokescreen egress rules for vast.ai IP range
6. Test fallback chain: local → vast.ai → cloud

### Phase 3: Optimization (Week 4+)

1. Analyze LiteLLM cost/usage dashboards (Prometheus + Grafana)
2. Tune model assignment — which tasks go where
3. Consider fine-tuning on domain-specific data (QLoRA on vast.ai)
4. Evaluate MiMo-V2-Flash or newer models as they release
5. Auto-scaling: script to spin up/down vast.ai instances based on queue depth

---

## Decision Matrix: Model Selection Guide

| Task Type | Recommended Tier | Model | Why |
|-----------|-----------------|-------|-----|
| Summarization | Tier 1 (local) | Qwen3 8B | Fast, free, good enough |
| Classification / routing | Tier 1 (local) | Phi-4-mini | Fastest option |
| Simple code generation | Tier 1 (local) | Llama 3.3 8B | Good tool calling support |
| Complex reasoning | Tier 2 (vast.ai) | Qwen3.5 30B | Near-frontier quality |
| Multi-step tool chains | Tier 2 (vast.ai) | Llama 3.3 70B | Best open-weight for agents |
| Safety-critical / injection-resistant | Tier 3 (cloud) | Claude Opus | Strongest instruction following |
| Math / science reasoning | Tier 2 (vast.ai) | DeepSeek-R1-70B | Specialized reasoning model |

---

## Open Questions

1. **Memory channel population**: How many DIMMs are installed? Maximizing channels is critical for CPU inference throughput.
2. **Vast.ai budget cap**: What monthly budget for GPU rental? This determines whether to run 24/7 or on-demand.
3. **Fine-tuning interest**: Want to fine-tune a model on your specific agent workflows? QLoRA on vast.ai is ~$5-10 per training run.
4. **Persistent vast.ai vs on-demand**: Always-on instance (~$150/mo) vs spin-up-on-demand (cheaper but ~60s cold start)?

---

## Sources

- [Best Open Source LLMs February 2026](https://whatllm.org/blog/best-open-source-models-february-2026)
- [Ollama vs vLLM Performance Benchmark 2026 (SitePoint)](https://www.sitepoint.com/ollama-vs-vllm-performance-benchmark-2026/)
- [Enterprise Local LLM Deployment 2026 (SitePoint)](https://www.sitepoint.com/the-2026-definitive-guide-to-running-local-llms-in-production/)
- [Vast.ai Hybrid Inference with LiteLLM](https://vast.ai/article/hybrid-ai-inference-local-litellm-proxy-with-remote-vast-ai-gpu)
- [Vast.ai vLLM Documentation](https://docs.vast.ai/vllm-llm-inference-and-serving)
- [vLLM on Vast.ai — Online Inference Guide](https://vast.ai/article/serving-online-inference-with-vllm-api-on-vast)
- [Self-Hosted LLM Guide 2026 (PremAI)](https://blog.premai.io/self-hosted-llm-guide-setup-tools-cost-comparison-2026/)
- [LiteLLM Ollama Provider Docs](https://docs.litellm.ai/docs/providers/ollama)
- [AMD EPYC LLM Inference Benchmarks](https://ahelpme.com/ai/llm-inference-benchmarks-with-llamacpp-with-amd-epyc-9554-cpu/)
- [Unlocking LLM Performance on AMD EPYC (AMD Blog)](https://www.amd.com/en/blogs/2025/unlocking-optimal-llm-performance-on-amd-epyc--cpus-with-vllm.html)
- [CPU Performance Discussion — llama.cpp](https://github.com/ggml-org/llama.cpp/discussions/3167)
- [Ollama vs vLLM Comprehensive Guide (Medium)](https://medium.com/@mustafa.gencc94/ollama-vs-vllm-a-comprehensive-guide-to-local-llm-serving-91705ec50c1d)
- [Self-Hosted LLM Leaderboard (Onyx AI)](https://onyx.app/self-hosted-llm-leaderboard)
- [Contabo Open Source LLMs Guide](https://contabo.com/blog/open-source-llms/)
