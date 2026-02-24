# SIB-K8s

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Helm](https://img.shields.io/badge/Helm-3.x-blue.svg)](https://helm.sh)

SIEM in a Box for Kubernetes — an umbrella Helm chart that combines [Falco](https://falco.org/) runtime detection with AI-powered alert analysis. Supports AWS EKS, Google GKE, Azure AKS, and generic Kubernetes clusters.

## Architecture

```
K8s Audit Sources (webhook / CloudWatch / Cloud Logging / Event Hub)
                    ↓
              Falco (detection)
                    ↓
           Falcosidekick (routing)
             ↙            ↘
          Loki           Analyzer
         (logs)       (AI + obfuscation)
           ↘              ↓
            ↘        LLM Provider
             ↘     (Ollama/OpenAI/Anthropic)
              ↘         ↙
            Grafana (dashboards)
```

## Features

- **Multi-cloud audit support** — `k8saudit` (webhook), `k8saudit-eks`, `k8saudit-gke`, `k8saudit-aks`
- **Runtime detection** — syscall monitoring with Falco (eBPF)
- **AI analysis** — privacy-preserving alert analysis with MITRE ATT&CK mapping
- **Obfuscation** — three levels (minimal / standard / paranoid) to protect sensitive data before LLM calls
- **Dashboards** — pre-built Grafana dashboards for security events and audit logs
- **Alert routing** — Falcosidekick integration (Slack, Teams, PagerDuty, etc.)

## Prerequisites

- Kubernetes 1.25+
- Helm 3.x
- Linux kernel 5.8+ (for `modern_ebpf` syscall driver)
- LLM provider access (Ollama, OpenAI, or Anthropic)

## Quick Start

```bash
# From local chart
git clone https://github.com/matijazezelj/sib-k8s.git
cd sib-k8s
helm dependency update
```

Install with the appropriate values file for your environment:

```bash
# Generic Kubernetes (webhook)
helm install sib-k8s . -f values-k8saudit.yaml -n sib-k8s --create-namespace

# AWS EKS
helm install sib-k8s . -f values-eks.yaml \
  --set auditPlugin.k8sauditEks.logGroup="/aws/eks/my-cluster/cluster" \
  --set auditPlugin.k8sauditEks.region="us-east-1" \
  -n sib-k8s --create-namespace

# Google GKE
helm install sib-k8s . -f values-gke.yaml \
  --set auditPlugin.k8sauditGke.projectId="my-project" \
  --set auditPlugin.k8sauditGke.clusterId="my-cluster" \
  --set auditPlugin.k8sauditGke.location="us-central1" \
  -n sib-k8s --create-namespace

# Azure AKS
helm install sib-k8s . -f values-aks.yaml \
  --set auditPlugin.k8sauditAks.subscriptionId="..." \
  --set auditPlugin.k8sauditAks.resourceGroup="my-rg" \
  --set auditPlugin.k8sauditAks.clusterName="my-cluster" \
  --set auditPlugin.k8sauditAks.eventHubNamespace="my-eh-ns" \
  -n sib-k8s --create-namespace
```

See [docs/cloud-agnostic-scenarios.md](docs/cloud-agnostic-scenarios.md) for detailed cloud-specific setup (IAM roles, Workload Identity, Event Hub, etc.).

## Configuration

### Audit Plugin

Set `auditPlugin.type` to one of:

| Value | Source | Auth |
|-------|--------|------|
| `k8saudit` | Webhook | None (requires API server config) |
| `k8saudit-eks` | CloudWatch Logs | IRSA |
| `k8saudit-gke` | Cloud Logging | Workload Identity |
| `k8saudit-aks` | Event Hub | Workload Identity |

### Analysis Service

```yaml
analysis:
  enabled: true
  obfuscation:
    level: standard        # minimal, standard, paranoid
  llm:
    provider: ollama       # ollama, openai, anthropic
    ollama:
      url: http://ollama:11434
      model: llama3.1:8b
```

For OpenAI/Anthropic, provide an API key via a Kubernetes secret:

```bash
kubectl create secret generic openai-secret --from-literal=api-key=sk-xxx
```

```yaml
analysis:
  llm:
    provider: openai
    openai:
      existingSecret: openai-secret
      secretKey: api-key
      model: gpt-4o-mini
```

### Obfuscation Levels

| Level | What's Obfuscated |
|-------|-------------------|
| `minimal` | API keys, tokens, passwords |
| `standard` | + IPs, hostnames, usernames, container IDs |
| `paranoid` | + file paths, high-entropy strings |

### Accessing Services

```bash
# Grafana
kubectl port-forward -n sib-k8s svc/sib-k8s-grafana 3000:80
kubectl get secret -n sib-k8s sib-k8s-grafana -o jsonpath="{.data.admin-password}" | base64 -d

# Analysis service health
kubectl port-forward -n sib-k8s svc/sib-k8s-analysis 8080:8080
curl http://localhost:8080/health
```

## Chart Dependencies

| Chart | Version | Repository |
|-------|---------|------------|
| Falco | 4.20.0 | falcosecurity |
| Falcosidekick | 0.9.5 | falcosecurity |
| Loki | 6.24.0 | grafana |
| Grafana | 8.8.2 | grafana |

## Values Files

| File | Environment |
|------|-------------|
| `values.yaml` | Defaults (all options documented) |
| `values-eks.yaml` | AWS EKS |
| `values-gke.yaml` | Google GKE |
| `values-aks.yaml` | Azure AKS |
| `values-k8saudit.yaml` | Generic webhook |

## Security

All containers run with a hardened security context (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop ALL` capabilities, `seccompProfile: RuntimeDefault`). The only exception is `hostNetwork` for the webhook receiver, which is required for API server connectivity. See `.trivyignore` for documented exceptions.

```bash
# Scan for vulnerabilities
trivy fs --scanners vuln,secret,misconfig .
```

## Documentation

- [Cloud-Agnostic Deployment Scenarios](docs/cloud-agnostic-scenarios.md) — detailed setup for each cloud provider
- [Talos Audit Setup](docs/talos-audit-setup.md) — configuring audit webhooks on Talos Linux

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgments

- [Falco](https://falco.org/) — runtime security
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) — alert routing
- [Grafana](https://grafana.com/) & [Loki](https://grafana.com/oss/loki/) — observability
- [SIB](https://github.com/matijazezelj/sib) — original SIEM in a Box project
