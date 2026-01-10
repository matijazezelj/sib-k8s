# Talos K8s Audit Configuration
# ==============================
# 
# To enable K8s audit events in Talos, you need to configure the API server
# to send audit logs to the k8saudit webhook receiver.
#
# The k8saudit webhook is available at:
#   - From within cluster: http://sib-k8s-k8saudit.sib-k8s.svc:9765/k8s-audit
#   - Via NodePort: http://<NODE_IP>:30007/k8s-audit
#   - Via localhost (hostNetwork): http://127.0.0.1:9765/k8s-audit
#
# Option 1: Using talosctl patch (recommended)
# --------------------------------------------

# First, create an audit policy file. Save this as audit-policy.yaml:
cat <<'EOF' > /tmp/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests at the Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods", "services", "namespaces"]
  - level: Metadata
    resources:
    - group: "apps"
      resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  - level: Metadata
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  # Log exec/attach at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # Don't log watch requests
  - level: None
    verbs: ["watch", "list"]
  # Don't log system:apiserver user
  - level: None
    users: ["system:apiserver"]
  # Catch-all for other requests
  - level: Metadata
EOF

# Then create the Talos machine config patch:
cat <<'EOF' > /tmp/talos-audit-patch.yaml
machine:
  files:
    - path: /var/lib/kubernetes/audit-policy.yaml
      permissions: 0644
      content: |
        apiVersion: audit.k8s.io/v1
        kind: Policy
        rules:
          - level: Metadata
            resources:
            - group: ""
              resources: ["secrets", "configmaps", "pods", "services", "namespaces"]
          - level: Metadata
            resources:
            - group: "apps"
              resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
          - level: Metadata
            resources:
            - group: "rbac.authorization.k8s.io"
              resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
          - level: RequestResponse
            resources:
            - group: ""
              resources: ["pods/exec", "pods/attach", "pods/portforward"]
          - level: None
            verbs: ["watch", "list"]
          - level: None
            users: ["system:apiserver"]
          - level: Metadata

cluster:
  apiServer:
    extraArgs:
      audit-policy-file: /var/lib/kubernetes/audit-policy.yaml
      audit-webhook-config-file: /var/lib/kubernetes/audit-webhook.yaml
      audit-webhook-batch-max-wait: 5s
    extraVolumes:
      - name: audit-policy
        hostPath: /var/lib/kubernetes/audit-policy.yaml
        mountPath: /var/lib/kubernetes/audit-policy.yaml
        readonly: true
      - name: audit-webhook
        hostPath: /var/lib/kubernetes/audit-webhook.yaml
        mountPath: /var/lib/kubernetes/audit-webhook.yaml
        readonly: true
  files:
    - path: /var/lib/kubernetes/audit-webhook.yaml
      permissions: 0644
      content: |
        apiVersion: v1
        kind: Config
        clusters:
        - name: falco
          cluster:
            server: http://sib-k8s-k8saudit.sib-k8s.svc:9765/k8s-audit
        contexts:
        - name: default
          context:
            cluster: falco
        current-context: default
EOF

# Apply the patch to your Talos node:
# talosctl patch mc -n <TALOS_NODE_IP> --patch @/tmp/talos-audit-patch.yaml

# Option 2: Manual talosctl edit
# ------------------------------
# talosctl edit machineconfig -n <TALOS_NODE_IP>

# Option 3: If using Talos with controlplane config
# -------------------------------------------------
# Add the following to your controlplane.yaml:
#
# cluster:
#   apiServer:
#     auditPolicy:
#       apiVersion: audit.k8s.io/v1
#       kind: Policy
#       rules:
#         - level: Metadata
#           resources:
#             - group: ""
#               resources: ["*"]
#
# Note: Talos 1.5+ supports inline auditPolicy configuration

# After applying the config, the API server will restart and start
# sending audit events to the k8saudit webhook.

# To verify audit events are being received:
# kubectl logs -n sib-k8s -l app.kubernetes.io/component=k8saudit -f
