# Cloud-Agnostic K8s Audit Scenarios

This document outlines the different deployment scenarios for SIB-K8s across various Kubernetes environments. The Helm chart now supports a unified approach where you simply set `auditPlugin.type` to configure the appropriate plugin for your cloud provider.

## Quick Reference

| Cloud/Platform | Plugin Type | Audit Source | Auth Method | Latency |
|----------------|-------------|--------------|-------------|---------|
| Generic K8s | `k8saudit` | Webhook | None | Real-time |
| AWS EKS | `k8saudit-eks` | CloudWatch Logs | IRSA | 10-30s |
| Google GKE | `k8saudit-gke` | Cloud Logging | Workload Identity | 5-15s |
| Azure AKS | `k8saudit-aks` | Event Hub | Workload Identity | ~5s |

---

## Scenario 1: Generic Kubernetes (Webhook)

**Use Cases:**
- Self-managed Kubernetes (kubeadm, kubespray)
- k3s / k0s / RKE2
- Talos Linux
- On-premises clusters
- Any cluster with API server access

### Architecture

```
┌─────────────────────┐      HTTP POST       ┌──────────────────┐
│  Kubernetes         │ ─────────────────────▶│  k8saudit        │
│  API Server         │    (audit events)    │  (webhook)       │
│                     │                      │  Port: 9765      │
└─────────────────────┘                      └────────┬─────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │  Falco Rules     │
                                             │  Engine          │
                                             └──────────────────┘
```

### Installation

```bash
helm install sib-k8s . \
  -f values-k8saudit.yaml \
  -n sib-k8s --create-namespace
```

### Prerequisites

1. **API Server Configuration Required** - You need control plane access to configure:
   - Audit policy file
   - Audit webhook configuration
   - API server flags

2. **Network Connectivity** - API server must reach the webhook endpoint

### Configuration Steps

1. Create audit policy (`/etc/kubernetes/audit-policy.yaml`):
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "services", "secrets", "configmaps"]
  - level: Metadata
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["*"]
  - level: Metadata
    omitStages:
      - RequestReceived
```

2. Create webhook config (`/etc/kubernetes/audit-webhook.yaml`):
```yaml
apiVersion: v1
kind: Config
clusters:
  - name: falco
    cluster:
      server: http://<NODE_IP>:30007/k8s-audit
contexts:
  - name: default
    context:
      cluster: falco
current-context: default
```

3. Add API server flags:
```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
--audit-webhook-batch-max-wait=5s
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Real-time events (lowest latency) | Requires API server config access |
| No cloud dependencies | May require node restart |
| Works on any K8s distribution | Uses hostNetwork (security consideration) |
| No additional costs | Manual webhook setup |

---

## Scenario 2: AWS EKS (CloudWatch)

**Use Cases:**
- Amazon EKS Standard clusters
- Amazon EKS Fargate
- EKS Anywhere (with CloudWatch integration)

### Architecture

```
┌─────────────────────┐                      ┌──────────────────┐
│  EKS API Server     │ ────────────────────▶│  CloudWatch      │
│  (managed)          │    audit logging     │  Logs            │
└─────────────────────┘                      └────────┬─────────┘
                                                      │ poll
                                                      ▼
                                             ┌──────────────────┐
                                             │  k8saudit-eks    │
                                             │  (plugin)        │
                                             └────────┬─────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │  Falco Rules     │
                                             │  Engine          │
                                             └──────────────────┘
```

### Installation

```bash
# 1. Enable EKS audit logging
aws eks update-cluster-config \
  --name my-cluster \
  --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'

# 2. Create IAM policy
cat > /tmp/falco-eks-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/eks/*/cluster:*"
    }
  ]
}
EOF
aws iam create-policy --policy-name FalcoEKSAuditPolicy \
  --policy-document file:///tmp/falco-eks-policy.json

# 3. Create IRSA
eksctl create iamserviceaccount \
  --name sib-k8s-k8saudit \
  --namespace sib-k8s \
  --cluster my-cluster \
  --attach-policy-arn arn:aws:iam::ACCOUNT_ID:policy/FalcoEKSAuditPolicy \
  --approve

# 4. Install with EKS values
helm install sib-k8s . \
  -f values-eks.yaml \
  --set auditPlugin.k8sauditEks.logGroup="/aws/eks/my-cluster/cluster" \
  --set auditPlugin.k8sauditEks.region="us-east-1" \
  --set auditPlugin.k8sauditEks.iamRoleArn="arn:aws:iam::ACCOUNT_ID:role/eksctl-...-Role1-..." \
  -n sib-k8s --create-namespace
```

### Key Configuration

```yaml
auditPlugin:
  type: k8saudit-eks
  k8sauditEks:
    region: us-east-1
    logGroup: "/aws/eks/my-cluster/cluster"
    logStream: "kube-apiserver-audit-*"
    shift: 10           # Time shift for polling
    pollingInterval: 5  # Seconds between polls
    useIRSA: true
    iamRoleArn: "arn:aws:iam::123456789012:role/falco-eks-role"
```

### Pros & Cons

| Pros | Cons |
|------|------|
| No API server config needed | 10-30s latency (polling) |
| Managed audit log storage | CloudWatch costs |
| Native AWS integration | Requires IRSA setup |
| Works with Fargate | Log group must exist |

---

## Scenario 3: Google GKE (Cloud Logging)

**Use Cases:**
- GKE Standard clusters
- GKE Autopilot clusters
- Anthos on GKE

### Architecture

```
┌─────────────────────┐                      ┌──────────────────┐
│  GKE API Server     │ ────────────────────▶│  Cloud Logging   │
│  (managed)          │    audit logging     │                  │
└─────────────────────┘    (automatic)       └────────┬─────────┘
                                                      │ poll
                                                      ▼
                                             ┌──────────────────┐
                                             │  k8saudit-gke    │
                                             │  (plugin)        │
                                             └────────┬─────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │  Falco Rules     │
                                             │  Engine          │
                                             └──────────────────┘
```

### Installation

```bash
# 1. Create GCP service account
gcloud iam service-accounts create falco-gke-audit \
  --display-name="Falco GKE Audit Logs Reader"

# 2. Grant permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:falco-gke-audit@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.viewer"

# 3. Configure Workload Identity
gcloud iam service-accounts add-iam-policy-binding \
  falco-gke-audit@PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT_ID.svc.id.goog[sib-k8s/sib-k8s-k8saudit]"

# 4. Install with GKE values
helm install sib-k8s . \
  -f values-gke.yaml \
  --set auditPlugin.k8sauditGke.projectId="my-project" \
  --set auditPlugin.k8sauditGke.clusterId="my-cluster" \
  --set auditPlugin.k8sauditGke.location="us-central1" \
  --set auditPlugin.k8sauditGke.serviceAccountEmail="falco-gke-audit@my-project.iam.gserviceaccount.com" \
  -n sib-k8s --create-namespace
```

### Key Configuration

```yaml
auditPlugin:
  type: k8saudit-gke
  k8sauditGke:
    projectId: "my-gcp-project"
    clusterId: "my-gke-cluster"
    location: "us-central1"        # Region or zone
    pollingInterval: 5
    useWorkloadIdentity: true
    serviceAccountEmail: "falco-gke-audit@my-project.iam.gserviceaccount.com"
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Audit logs enabled by default | 5-15s latency (polling) |
| Native GCP integration | Cloud Logging costs |
| Works with Autopilot | Workload Identity setup |
| No API server access needed | IAM configuration required |

---

## Scenario 4: Azure AKS (Event Hub)

**Use Cases:**
- Azure AKS clusters
- AKS with Azure Monitor integration
- Azure Arc-enabled Kubernetes

### Architecture

```
┌─────────────────────┐      Diagnostic      ┌──────────────────┐
│  AKS API Server     │ ────────────────────▶│  Azure Event Hub │
│  (managed)          │      Settings        │                  │
└─────────────────────┘                      └────────┬─────────┘
                                                      │ stream
                                                      ▼
                                             ┌──────────────────┐
                                             │  k8saudit-aks    │
                                             │  (plugin)        │
                                             └────────┬─────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │  Falco Rules     │
                                             │  Engine          │
                                             └──────────────────┘
```

### Installation

```bash
# 1. Create Event Hub namespace
az eventhubs namespace create \
  --name my-eventhub-ns \
  --resource-group my-rg \
  --location eastus

# 2. Create Event Hub
az eventhubs eventhub create \
  --name insights-logs-kube-audit \
  --namespace-name my-eventhub-ns \
  --resource-group my-rg

# 3. Configure AKS diagnostic settings
AKS_ID=$(az aks show -g my-rg -n my-cluster --query id -o tsv)
EH_RULE=$(az eventhubs namespace authorization-rule list \
  --namespace-name my-eventhub-ns \
  --resource-group my-rg \
  --query "[?name=='RootManageSharedAccessKey'].id" -o tsv)

az monitor diagnostic-settings create \
  --name aks-audit-to-eventhub \
  --resource $AKS_ID \
  --event-hub insights-logs-kube-audit \
  --event-hub-rule $EH_RULE \
  --logs '[{"category":"kube-audit","enabled":true}]'

# 4. Create Managed Identity for Workload Identity
az identity create \
  --name falco-aks-identity \
  --resource-group my-rg

CLIENT_ID=$(az identity show -g my-rg -n falco-aks-identity --query clientId -o tsv)

# 5. Assign Event Hub Data Receiver role
az role assignment create \
  --assignee $CLIENT_ID \
  --role "Azure Event Hubs Data Receiver" \
  --scope $(az eventhubs namespace show -g my-rg -n my-eventhub-ns --query id -o tsv)

# 6. Create federated credential
az identity federated-credential create \
  --name falco-federated-cred \
  --identity-name falco-aks-identity \
  --resource-group my-rg \
  --issuer $(az aks show -g my-rg -n my-cluster --query oidcIssuerProfile.issuerUrl -o tsv) \
  --subject system:serviceaccount:sib-k8s:sib-k8s-k8saudit

# 7. Install with AKS values
helm install sib-k8s . \
  -f values-aks.yaml \
  --set auditPlugin.k8sauditAks.eventHubNamespace="my-eventhub-ns" \
  --set auditPlugin.k8sauditAks.eventHubName="insights-logs-kube-audit" \
  --set auditPlugin.k8sauditAks.clientId="$CLIENT_ID" \
  --set auditPlugin.k8sauditAks.tenantId="$(az account show --query tenantId -o tsv)" \
  -n sib-k8s --create-namespace
```

### Key Configuration

```yaml
auditPlugin:
  type: k8saudit-aks
  k8sauditAks:
    eventHubNamespace: "my-eventhub-namespace"
    eventHubName: "insights-logs-kube-audit"
    consumerGroup: "$Default"
    useWorkloadIdentity: true
    clientId: "00000000-0000-0000-0000-000000000000"
    tenantId: "00000000-0000-0000-0000-000000000000"
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Low latency (streaming) | Event Hub infrastructure needed |
| Native Azure integration | More complex setup |
| Scalable architecture | Diagnostic settings required |
| Works with Azure Arc | Workload Identity configuration |

---

## Comparison Matrix

### Feature Comparison

| Feature | Generic | EKS | GKE | AKS |
|---------|---------|-----|-----|-----|
| Real-time events | Yes | No | No | Near real-time |
| Managed audit storage | No | Yes | Yes | Yes |
| API server access needed | Yes | No | No | No |
| Cloud IAM integration | No | IRSA | Workload ID | Workload ID |
| Additional cloud costs | No | CloudWatch | Logging | Event Hub |
| Works on Fargate/Autopilot | N/A | Yes | Yes | N/A |
| hostNetwork required | Yes | No | No | No |

### When to Use Each

| If you have... | Use... |
|----------------|--------|
| Self-managed K8s with API server access | `k8saudit` (webhook) |
| AWS EKS cluster | `k8saudit-eks` |
| Google GKE cluster | `k8saudit-gke` |
| Azure AKS cluster | `k8saudit-aks` |
| Multi-cloud with webhook available | `k8saudit` (webhook) |
| Compliance requirement for audit retention | Cloud-native plugins |

---

## Troubleshooting

### Generic Webhook Issues

```bash
# Check if webhook is receiving events
kubectl logs -n sib-k8s deploy/sib-k8s-k8saudit -f

# Verify API server can reach webhook
kubectl exec -n kube-system <api-server-pod> -- curl http://<webhook-ip>:9765/healthz
```

### EKS CloudWatch Issues

```bash
# Verify CloudWatch log group exists
aws logs describe-log-groups --log-group-name-prefix /aws/eks/

# Check IRSA is working
kubectl exec -n sib-k8s deploy/sib-k8s-k8saudit -- aws sts get-caller-identity
```

### GKE Cloud Logging Issues

```bash
# Verify Workload Identity
kubectl exec -n sib-k8s deploy/sib-k8s-k8saudit -- gcloud auth list

# Check audit logs exist
gcloud logging read 'resource.type="k8s_cluster"' --limit 5
```

### AKS Event Hub Issues

```bash
# Verify diagnostic settings
az monitor diagnostic-settings list --resource <aks-resource-id>

# Check Event Hub is receiving data
az eventhubs eventhub show \
  --name insights-logs-kube-audit \
  --namespace-name my-eventhub-ns \
  --resource-group my-rg
```

---

## Migration Between Scenarios

To switch from one audit source to another:

1. Update `auditPlugin.type` in your values
2. Configure the new plugin's settings
3. Run `helm upgrade`:

```bash
# Example: Switch from webhook to EKS
helm upgrade sib-k8s . \
  --set auditPlugin.type=k8saudit-eks \
  --set auditPlugin.k8sauditEks.logGroup="/aws/eks/cluster/cluster" \
  --set auditPlugin.k8sauditEks.region="us-east-1" \
  -n sib-k8s
```

The previous resources will be automatically cleaned up and new ones created.
