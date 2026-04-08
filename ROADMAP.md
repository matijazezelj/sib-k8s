# Roadmap

Planned improvements, roughly in priority order. Not a commitment — open an issue to discuss or contribute.

---

## In Progress

- **Cloud provider audit plugins** — native EKS (CloudWatch), GKE (Cloud Logging), and AKS (Event Hub) plugin support without a webhook forwarder. Values files (`values-eks.yaml`, `values-gke.yaml`, `values-aks.yaml`) exist as templates; the deployment wiring is pending.

---

## Planned

### Chart

- **Helm chart on ArtifactHub** — publish to ArtifactHub with OCI registry support so users can install without cloning the repo
- **Cert-manager integration** — auto-generate TLS certificate for the audit webhook receiver instead of requiring manual cert setup
- **Horizontal pod autoscaling** for the analyzer service under alert bursts
- **NetworkPolicy templates** — default-deny with explicit allow rules for all inter-component traffic

### Analyzer

- **Streaming analysis** — Server-Sent Events endpoint so Grafana can show analysis results in real time without polling
- **Alert deduplication** — group repeated alerts before sending to LLM to reduce token usage
- **Structured MITRE output** — return ATT&CK technique IDs as machine-readable JSON fields, not just in prose
- **Feedback loop** — mark analysis results as false positive / confirmed from Grafana and feed back to improve future prompts

### Observability

- **Grafana alert rules** — pre-built alerting rules for critical detections (cluster-admin binding, privileged pod, secret access)
- **SLO dashboard** — analyzer latency, LLM error rate, cache hit rate
- **VictoriaMetrics stack option** — lighter-weight alternative to Loki + Grafana for resource-constrained clusters

### Security

- **SBOM generation** — produce a Software Bill of Materials for the analyzer image on every release
- **Signed images** — cosign signatures for the analyzer container image

---

## Won't Do (in this repo)

- **Syscall rule packs** (webshell detection, cloud CLI abuse, etc.) — these belong in [SIB](https://github.com/matijazezelj/sib) which targets Linux hosts via Docker Compose. The Falco DaemonSet in sib-k8s picks up syscall events automatically via the upstream `falco_rules.yaml`.
- **Multi-tenant RBAC** — out of scope; use namespace isolation and standard K8s RBAC.
