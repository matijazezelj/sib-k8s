---
layout: default
title: Upgrade Guide
---

# Upgrade Guide

## General process

1. Pull the latest chart:
   ```bash
   git pull origin main
   ```

2. Update chart dependencies:
   ```bash
   helm dependency update
   ```

3. Upgrade the release:
   ```bash
   helm upgrade sib-k8s . -f values-<your-environment>.yaml -n sib-k8s
   ```

4. Verify all pods are healthy:
   ```bash
   kubectl get pods -n sib-k8s
   ```

---

## Version-specific notes

### 0.3.0

No breaking changes. Upgrade with the standard process above.

**New docs**

- `docs/cloud-agnostic-scenarios.md` — deployment patterns for EKS, GKE, AKS
- `docs/talos-audit-setup.md` — Talos Linux webhook setup

---

### 0.2.0

**Multi-cloud audit plugin support**

`auditPlugin.type` now accepts `k8saudit-eks`, `k8saudit-gke`, and `k8saudit-aks`
in addition to the default `k8saudit` webhook mode.

If you were using `values-eks.yaml`, `values-gke.yaml`, or `values-aks.yaml`,
check the updated cloud-specific values and add any required fields:

- **EKS**: `auditPlugin.k8sauditEks.logGroup` and `.region`
- **GKE**: `auditPlugin.k8sauditGke.projectId`, `.clusterId`, `.location`
- **AKS**: `auditPlugin.k8sauditAks.subscriptionId`, `.resourceGroup`, `.clusterName`, `.eventHubNamespace`

**Security context changes**

All containers now enforce `readOnlyRootFilesystem: true`. If you have custom
sidecars or init containers that write to the filesystem, add a writable
`emptyDir` volume mount for their temp paths.

---

### 0.1.0

Initial release — no upgrade path from a previous version.

---

## Rolling back

```bash
helm rollback sib-k8s -n sib-k8s
```

To roll back to a specific revision:
```bash
helm history sib-k8s -n sib-k8s       # list revisions
helm rollback sib-k8s <revision> -n sib-k8s
```

## Getting help

- Run `kubectl get events -n sib-k8s` to diagnose pod failures
- See [Troubleshooting](troubleshooting.md) for common issues
- Open an issue at [github.com/matijazezelj/sib-k8s](https://github.com/matijazezelj/sib-k8s/issues)
