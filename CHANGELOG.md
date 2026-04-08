# Changelog

All notable changes to SIB-K8s are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed
- Simplified k8saudit deployment to webhook mode only (cloud plugins moved to dedicated values files)

---

## [0.3.0] - 2026-02-24

### Added
- Comparison table in README: SIB-K8s vs Falco standalone, Sysdig, Aqua, Wazuh
- `docs/cloud-agnostic-scenarios.md`: deployment patterns for EKS, GKE, AKS
- `docs/talos-audit-setup.md`: Talos Linux API server webhook configuration

### Fixed
- Health check port in troubleshooting guide
- Dead code and stale configuration removed from templates

---

## [0.2.0] - 2026-01-21

### Added
- Multi-cloud k8saudit support: EKS (CloudWatch), GKE (Cloud Logging), AKS (Event Hub)
- IRSA / Workload Identity annotations for cloud plugin service accounts
- AWS credential secret, GCP credentials volume, Azure client secret for cloud deployments
- Checksum annotations on k8saudit Deployment for config change detection

### Changed
- All containers hardened: `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`
- Falcosidekick and Grafana security contexts tightened
- Trivy security scan exceptions documented in `.trivyignore` with justifications

---

## [0.1.0] - 2026-01-09

### Added
- Initial umbrella Helm chart: Falco DaemonSet, Falcosidekick, Loki, Grafana wired together
- k8saudit plugin support for Kubernetes API server audit log collection
- Falco k8saudit rules (`rules/k8s_audit_rules.yaml`) and GKE-specific overrides
- Analyzer service (FastAPI) with AI-powered alert analysis via Falcosidekick webhook
- Loki push from analyzer: analysis results stored alongside raw alerts
- GHCR builds for the analyzer image (`ghcr.io/matijazezelj/sib-k8s-analyzer`)
- Grafana pre-built dashboards for security events and audit logs
- Falcosidekick HTTP output to analyzer and Loki
- CI workflow: helm lint, helm template, analyzer Docker build
- Support for Ollama, OpenAI, and Anthropic as LLM providers
- Three obfuscation levels (minimal / standard / paranoid) for privacy-preserving LLM calls
