# 🛡️ SIB-K8s: SIEM in a Box for Kubernetes

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Helm](https://img.shields.io/badge/Helm-3.x-blue.svg)](https://helm.sh)

SIB-K8s is a comprehensive Kubernetes security monitoring solution delivered as an umbrella Helm chart. It combines runtime security detection with AI-powered alert analysis, providing enterprise-grade security monitoring with privacy-preserving features.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SIB-K8s                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        K8s Audit Sources                              │   │
│  │  ┌─────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │   │
│  │  │k8saudit │  │k8saudit-eks │  │k8saudit-gke │  │k8saudit-aks │     │   │
│  │  │(webhook)│  │(CloudWatch) │  │(Cloud Log)  │  │(Event Hub)  │     │   │
│  │  └────┬────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │   │
│  └───────┴──────────────┴────────────────┴────────────────┴─────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌──────────────┐     ┌─────────────────┐     ┌───────────────────────────┐ │
│  │    Falco     │     │  Falcosidekick  │     │          Loki             │ │
│  │  (Detection) │────▶│   (Fan-out)     │────▶│    (Log Storage)          │ │
│  │              │     │                 │     │                           │ │
│  └──────────────┘     └─────────────────┘     └───────────────────────────┘ │
│         │                     │                            │                 │
│         │                     ▼                            ▼                 │
│         │            ┌─────────────────┐          ┌───────────────┐         │
│         │            │ Analysis Service │          │    Grafana    │         │
│         │            │  (AI + Obfusc)  │          │  (Dashboards) │         │
│         │            └─────────────────┘          └───────────────┘         │
│         │                     │                                              │
│         │                     ▼                                              │
│         │            ┌─────────────────┐                                     │
│         └───────────▶│   LLM Provider  │                                     │
│  (syscall events)    │ Ollama/OpenAI/  │                                     │
│                      │   Anthropic     │                                     │
│                      └─────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Multi-Cloud K8s Audit Support
- **Generic Kubernetes** (`k8saudit`): Webhook-based for any Kubernetes cluster
- **AWS EKS** (`k8saudit-eks`): Direct integration with CloudWatch Logs
- **Google GKE** (`k8saudit-gke`): Direct integration with Cloud Logging
- **Azure AKS** (`k8saudit-aks`): Direct integration with Event Hub

### Security Monitoring
- Runtime security detection with Falco
- Syscall-level monitoring (optional)
- K8s audit log analysis
- MITRE ATT&CK mapping

### AI-Powered Analysis
- Privacy-preserving alert analysis
- Three obfuscation levels: minimal, standard, paranoid
- Support for multiple LLM providers (Ollama, OpenAI, Anthropic)
- Automatic MITRE ATT&CK mapping
- Risk assessment and severity scoring
- Investigation recommendations

### Observability
- Centralized logging with Loki
- Pre-built Grafana dashboards
- Alert routing with Falcosidekick
- Integration with Slack, Teams, PagerDuty, and more

## 📋 Prerequisites

- Kubernetes 1.25+
- Helm 3.x
- For syscall monitoring: Linux kernel 5.8+ (for modern_ebpf driver)
- For AI analysis: Access to LLM provider (Ollama, OpenAI, or Anthropic)

## 🚀 Quick Start

### Add the Helm Repository

```bash
# Add the repository (when published)
helm repo add sib-k8s https://matijazezelj.github.io/sib-k8s
helm repo update

# Or install from local chart
git clone https://github.com/matijazezelj/sib-k8s.git
cd sib-k8s
```

### Install for Generic Kubernetes (Webhook)

```bash
helm install sib-k8s . \
  -f values-k8saudit.yaml \
  -n sib-k8s --create-namespace
```

### Install for AWS EKS

```bash
helm install sib-k8s . \
  -f values-eks.yaml \
  --set auditPlugin.k8sauditEks.logGroup="/aws/eks/my-cluster/cluster" \
  --set auditPlugin.k8sauditEks.region="us-east-1" \
  -n sib-k8s --create-namespace
```

### Install for Google GKE

```bash
helm install sib-k8s . \
  -f values-gke.yaml \
  --set auditPlugin.k8sauditGke.projectId="my-project" \
  --set auditPlugin.k8sauditGke.clusterId="my-cluster" \
  --set auditPlugin.k8sauditGke.location="us-central1" \
  -n sib-k8s --create-namespace
```

### Install for Azure AKS

```bash
helm install sib-k8s . \
  -f values-aks.yaml \
  --set auditPlugin.k8sauditAks.subscriptionId="..." \
  --set auditPlugin.k8sauditAks.resourceGroup="my-rg" \
  --set auditPlugin.k8sauditAks.clusterName="my-cluster" \
  --set auditPlugin.k8sauditAks.eventHubNamespace="my-eh-ns" \
  -n sib-k8s --create-namespace
```

## 📖 Configuration

### Selecting the K8s Audit Plugin

The `auditPlugin.type` value determines which plugin to use:

| Value | Description | Use Case |
|-------|-------------|----------|
| `k8saudit` | Webhook-based | Any K8s cluster with API server access |
| `k8saudit-eks` | CloudWatch integration | AWS EKS clusters |
| `k8saudit-gke` | Cloud Logging integration | Google GKE clusters |
| `k8saudit-aks` | Event Hub integration | Azure AKS clusters |

### Syscall Monitoring

Enable syscall monitoring for host-level detection:

```yaml
syscallMonitoring:
  enabled: true
  driverKind: modern_ebpf  # or: kmod, ebpf, auto
```

### Analysis Service Configuration

Configure AI-powered analysis:

```yaml
analysis:
  enabled: true
  
  obfuscation:
    level: standard  # minimal, standard, paranoid
  
  llm:
    provider: ollama  # or: openai, anthropic
    
    ollama:
      url: http://ollama:11434
      model: llama3.1:8b
    
    # For OpenAI:
    # openai:
    #   existingSecret: openai-api-key
    #   secretKey: api-key
    #   model: gpt-4o-mini
```

### Output Configuration

Configure where alerts are sent:

```yaml
falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: "https://hooks.slack.com/services/..."
    
    teams:
      webhookurl: "https://outlook.office.com/webhook/..."
    
    pagerduty:
      routingkey: "..."
```

## 🔒 Privacy & Obfuscation

The analysis service implements privacy-preserving obfuscation to protect sensitive data before sending to LLM providers:

### Obfuscation Levels

| Level | Description | What's Obfuscated |
|-------|-------------|-------------------|
| `minimal` | Only credentials | API keys, tokens, passwords |
| `standard` | Recommended | + IPs, hostnames, usernames, container IDs |
| `paranoid` | Maximum privacy | + File paths, high-entropy strings |

### What Gets Protected

- AWS/GCP/Azure credentials and tokens
- GitHub/GitLab tokens
- Database connection strings
- Private keys and certificates
- Internal IP addresses and hostnames
- Usernames and email addresses
- Container and pod IDs

## 📊 Grafana Dashboards

Pre-built dashboards included:

1. **SIB-K8s Overview**: Summary of all security events
2. **K8s Audit Events**: Kubernetes API audit analysis

Access Grafana:
```bash
kubectl port-forward -n sib-k8s svc/sib-k8s-grafana 3000:80
# Open http://localhost:3000
# Get password: kubectl get secret -n sib-k8s sib-k8s-grafana -o jsonpath="{.data.admin-password}" | base64 -d
```

## 🔧 Advanced Configuration

### Custom Falco Rules

```yaml
customRules:
  enabled: true
  rules: |
    - rule: My Custom Rule
      desc: Detect specific behavior
      condition: evt.type = open and fd.name contains "/sensitive"
      output: "Sensitive file access: %fd.name by %proc.name"
      priority: WARNING
      tags: [custom, sensitive]
```

### Network Policies

```yaml
networkPolicies:
  enabled: true
  allowedNamespaces:
    - kube-system
    - monitoring
```

### Service Monitor (Prometheus)

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus
```

## 🏷️ Chart Dependencies

| Dependency | Version | Repository |
|------------|---------|------------|
| Falco | 4.20.0 | falcosecurity |
| Falcosidekick | 0.9.5 | falcosecurity |
| Loki | 6.24.0 | grafana |
| Grafana | 8.8.2 | grafana |

## 📝 Example Values Files

- `values.yaml` - Default configuration
- `values-eks.yaml` - AWS EKS configuration
- `values-gke.yaml` - Google GKE configuration
- `values-aks.yaml` - Azure AKS configuration
- `values-k8saudit.yaml` - Generic K8s webhook configuration

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests.

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Falco](https://falco.org/) - Cloud native runtime security
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) - Alert routing
- [Grafana](https://grafana.com/) - Observability platform
- [Loki](https://grafana.com/oss/loki/) - Log aggregation
- [SIB](https://github.com/matijazezelj/sib) - Original SIEM in a Box project
