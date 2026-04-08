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

- **K8s audit log collection** — webhook receiver for generic Kubernetes clusters; cloud provider plugins (EKS, GKE, AKS) on the roadmap
- **Runtime detection** — syscall monitoring with Falco (eBPF)
- **AI analysis** — privacy-preserving alert analysis with MITRE ATT&CK mapping
- **Obfuscation** — three levels (minimal / standard / paranoid) to protect sensitive data before LLM calls
- **Dashboards** — pre-built Grafana dashboards for security events and audit logs
- **Alert routing** — Falcosidekick integration (Slack, Teams, PagerDuty, etc.)

## Why SIB-K8s?

There are several tools in the Kubernetes security space. Here's how SIB-K8s compares:

| | SIB-K8s | Falco + Falcosidekick | Sysdig Secure | Aqua / StackRox | Wazuh |
|---|---|---|---|---|---|
| Deployment | Single Helm chart | Manual wiring | SaaS / agent | SaaS / operator | Server + agents |
| AI analysis | Built-in (Ollama, OpenAI, Anthropic) | None | Proprietary | None | None |
| Privacy obfuscation | Yes (3 levels) | N/A | No (data sent to vendor) | No | No |
| Multi-cloud audit | EKS, GKE, AKS, webhook | Plugin per cloud | EKS, GKE | EKS, GKE, AKS | Manual config |
| MITRE ATT&CK mapping | Automatic (AI) | Manual rules | Yes | Yes | Yes |
| Dashboards | Included (Grafana) | BYO | Proprietary | Proprietary | Included |
| Cost | Free / open source | Free / open source | Commercial | Commercial | Free / commercial |
| Self-hosted LLM | Yes (Ollama) | N/A | No | No | No |

**Key differentiators:**

- **One `helm install`** — Falco, Falcosidekick, Loki, Grafana, and the AI analyzer are deployed and wired together automatically. No manual plumbing.
- **Privacy-first AI** — alerts are obfuscated before reaching any LLM. Sensitive data (IPs, secrets, hostnames) never leaves your control at standard/paranoid levels.
- **Bring your own LLM** — run Ollama in-cluster for fully air-gapped analysis, or use OpenAI/Anthropic when that's acceptable.
- **Cloud-native audit out of the box** — switch between webhook, CloudWatch, Cloud Logging, or Event Hub by changing a single value.

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

```bash
# Generic Kubernetes (webhook)
helm install sib-k8s . -f values-k8saudit.yaml -n sib-k8s --create-namespace
```

Then configure your API server to send audit events to the webhook — see [docs/cloud-agnostic-scenarios.md](docs/cloud-agnostic-scenarios.md) for per-provider setup (EKS, GKE, AKS, Talos).

## Configuration

### Audit Plugin

The default mode is `k8saudit` (webhook). Your API server posts audit events to the in-cluster receiver.

| Provider | How to route audit logs |
|----------|------------------------|
| Generic K8s | Configure `--audit-webhook-config-file` on kube-apiserver |
| AWS EKS | Enable CloudWatch audit logs, forward to webhook via Fluentbit/Vector |
| Google GKE | Cloud Logging → Pub/Sub → webhook forwarder |
| Azure AKS | Diagnostic settings → Event Hub → webhook forwarder |
| Talos Linux | See [docs/talos-audit-setup.md](docs/talos-audit-setup.md) |

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

| File | Purpose |
|------|---------|
| `values.yaml` | Defaults — all options documented |
| `values-k8saudit.yaml` | Generic Kubernetes (webhook) — start here |

## Security

All containers run with a hardened security context (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop ALL` capabilities, `seccompProfile: RuntimeDefault`). The only exception is `hostNetwork` for the webhook receiver, which is required for API server connectivity. See `.trivyignore` for documented exceptions.

```bash
# Scan for vulnerabilities
trivy fs --scanners vuln,secret,misconfig .
```

## Documentation

- [Cloud-Agnostic Deployment Scenarios](docs/cloud-agnostic-scenarios.md) — API server webhook setup for EKS, GKE, AKS, and generic clusters
- [Talos Audit Setup](docs/talos-audit-setup.md) — configuring audit webhooks on Talos Linux
- [Upgrade Guide](docs/upgrade.md) — version-specific upgrade instructions
- [Changelog](CHANGELOG.md) — full version history

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgments

- [Falco](https://falco.org/) — runtime security
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) — alert routing
- [Grafana](https://grafana.com/) & [Loki](https://grafana.com/oss/loki/) — observability
- [SIB](https://github.com/matijazezelj/sib) — original SIEM in a Box project
