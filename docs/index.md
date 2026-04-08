---
layout: default
title: SIB-K8s
nav_order: 1
---

# SIB-K8s

**SIEM in a Box for Kubernetes** — a single Helm chart that deploys Falco runtime detection, Loki log aggregation, Grafana dashboards, and an AI-powered alert analyzer wired together and ready to use.

[View on GitHub](https://github.com/matijazezelj/sib-k8s){: .btn } [Quick Start](https://github.com/matijazezelj/sib-k8s#quick-start){: .btn }

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Cloud-Agnostic Deployment Scenarios](cloud-agnostic-scenarios.md) | API server webhook setup for EKS, GKE, AKS, and generic clusters |
| [Talos Audit Setup](talos-audit-setup.md) | Configuring audit webhooks on Talos Linux |
| [Upgrade Guide](upgrade.md) | Version-specific upgrade instructions |

## Architecture

```
K8s Audit Sources (webhook)
        ↓
  Falco (detection)
        ↓
 Falcosidekick (routing)
   ↙            ↘
 Loki         Analyzer
(logs)     (AI + obfuscation)
  ↘              ↓
   ↘        LLM Provider
    ↘    (Ollama/OpenAI/Anthropic)
     ↘        ↙
    Grafana (dashboards)
```

## Related

- **[SIB](https://github.com/matijazezelj/sib)** — the Docker Compose version for Linux hosts and VMs
