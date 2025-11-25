# Talos Linux Security Hardening Guide

Comprehensive security hardening reference for production Talos deployments, covering secure boot, disk encryption, KMS integration, audit policies, and zero-trust architecture.

---

## Table of Contents

1. [Secure Boot Implementation](#secure-boot-implementation)
2. [Disk Encryption (LUKS2)](#disk-encryption-luks2)
3. [TPM Integration](#tpm-integration)
4. [KMS Integration for Secret Encryption](#kms-integration-for-secret-encryption)
5. [Kubernetes Audit Policies](#kubernetes-audit-policies)
6. [Network Security](#network-security)
7. [Pod Security Standards](#pod-security-standards)
8. [Certificate Management](#certificate-management)
9. [API Access Control](#api-access-control)
10. [Compliance Frameworks](#compliance-frameworks)

---

## Secure Boot Implementation

Secure Boot ensures the boot chain integrity by cryptographically verifying each component before execution.

### 1. Generate Secure Boot Keys

```bash
# Install required tools
apt-get install efitools openssl

# Create key directory
mkdir -p secureboot-keys
cd secureboot-keys

# Generate Platform Key (PK)
openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 \
  -sha256 -days 3650 -subj "/CN=Talos Platform Key/" -out PK.crt
openssl x509 -outform DER -in PK.crt -out PK.cer
cert-to-efi-sig-list -g "$(uuidgen)" PK.crt PK.esl
sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth

# Generate Key Exchange Key (KEK)
openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 \
  -sha256 -days 3650 -subj "/CN=Talos Key Exchange Key/" -out KEK.crt
openssl x509 -outform DER -in KEK.crt -out KEK.cer
cert-to-efi-sig-list -g "$(uuidgen)" KEK.crt KEK.esl
sign-efi-sig-list -a -k PK.key -c PK.crt KEK KEK.esl KEK.auth

# Generate Signature Database (db)
openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 \
  -sha256 -days 3650 -subj "/CN=Talos Signature Database/" -out db.crt
openssl x509 -outform DER -in db.crt -out db.cer
cert-to-efi-sig-list -g "$(uuidgen)" db.crt db.esl
sign-efi-sig-list -a -k KEK.key -c KEK.crt db db.esl db.auth

# Securely store keys (encrypt with age/SOPS)
age-encrypt -r <public-key> PK.key > PK.key.age
age-encrypt -r <public-key> KEK.key > KEK.key.age
age-encrypt -r <public-key> db.key > db.key.age
```

### 2. Build Custom Talos Image with Signed Kernel

```bash
# Clone Talos repository
git clone https://github.com/siderolabs/talos.git
cd talos

# Build custom installer with secure boot support
make installer PLATFORM=metal \
  PUSH=false \
  WITH_SECUREBOOT=true \
  SECUREBOOT_SIGNING_KEY=../secureboot-keys/db.key \
  SECUREBOOT_SIGNING_CERT=../secureboot-keys/db.crt

# Or use pre-built SecureBoot images from Talos (signed with Microsoft keys)
# and enroll additional keys for custom signing
```

### 3. Enroll Keys in UEFI Firmware

**Method 1: Via UEFI Setup UI**
1. Boot into UEFI setup
2. Navigate to Secure Boot settings
3. Enter "Key Management" or "Custom Mode"
4. Enroll PK, KEK, and db keys from USB drive

**Method 2: Via efitools (from Linux)**

```bash
# Boot into Linux environment with UEFI variables accessible
# Copy keys to EFI System Partition
mkdir -p /boot/efi/secureboot-keys
cp *.auth /boot/efi/secureboot-keys/

# Enroll keys (requires KeyTool or similar)
efi-updatevar -f PK.auth PK
efi-updatevar -a -f KEK.auth KEK
efi-updatevar -a -f db.auth db

# Reboot and enable Secure Boot in UEFI
```

### 4. Machine Config for Secure Boot

```yaml
machine:
  install:
    disk: /dev/sda
    image: ghcr.io/siderolabs/installer:v1.6.0-secureboot  # SecureBoot image

  features:
    apidCheckExtKeyUsage: true  # Strict certificate validation

  secureboot:
    # Verify secure boot status
    enabled: true
```

### 5. Verify Secure Boot

```bash
# Check secure boot status
talosctl -n 10.0.1.10 dmesg | grep -i "secure boot"

# Should show: "secureboot: Secure boot enabled"

# Verify kernel signature
talosctl -n 10.0.1.10 dmesg | grep -i "signature"

# Check EFI variables
talosctl -n 10.0.1.10 read /sys/firmware/efi/efivars/SecureBoot-*
```

---

## Disk Encryption (LUKS2)

### 1. TPM-Based Encryption (Recommended)

```yaml
machine:
  install:
    disk: /dev/sda
    wipe: true  # WARNING: Destroys all data

  systemDiskEncryption:
    # State partition (etcd data, machine config)
    state:
      provider: luks2
      keys:
        - slot: 0
          tpm: {}  # TPM 2.0 automatic unsealing

      # LUKS2 options for performance
      options:
        - no_read_workqueue
        - no_write_workqueue

      cipher: aes-xts-plain64
      keySize: 512
      blockSize: 4096

      # Performance optimization
      perf:
        pbkdf:
          algorithm: argon2id
          memory: 1048576  # 1GB
          iterations: 4
          parallelism: 4

    # Ephemeral partition (container images, logs)
    ephemeral:
      provider: luks2
      keys:
        - slot: 0
          tpm: {}

      options:
        - no_read_workqueue
        - no_write_workqueue

      cipher: aes-xts-plain64
      keySize: 512
```

### 2. Dual-Key Encryption (TPM + Recovery Passphrase)

```yaml
machine:
  systemDiskEncryption:
    state:
      provider: luks2
      keys:
        # Primary: TPM for automatic unsealing
        - slot: 0
          tpm: {}

        # Fallback: Static passphrase for disaster recovery
        - slot: 1
          static:
            passphrase: "${LUKS_RECOVERY_KEY}"  # From secrets manager

      options:
        - no_read_workqueue
        - no_write_workqueue

    ephemeral:
      provider: luks2
      keys:
        - slot: 0
          tpm: {}
        - slot: 1
          static:
            passphrase: "${LUKS_RECOVERY_KEY}"
```

**Managing recovery keys with SOPS**:

```bash
# Create secrets file
cat > secrets.enc.yaml <<EOF
luks_recovery_key: $(openssl rand -base64 32)
EOF

# Encrypt with SOPS
sops -e -i secrets.enc.yaml

# Reference in machine config (use envsubst)
export LUKS_RECOVERY_KEY=$(sops -d secrets.enc.yaml | yq .luks_recovery_key)
envsubst < controlplane.yaml.tpl > controlplane.yaml
```

### 3. KMS-Based Encryption (Enterprise)

```yaml
machine:
  systemDiskEncryption:
    state:
      provider: luks2
      keys:
        - slot: 0
          kms:
            endpoint: https://kms.example.com:8200
            token: "${KMS_TOKEN}"
```

### 4. Verify Disk Encryption

```bash
# Check encryption status
talosctl -n 10.0.1.10 get encryptionconfig

# View disk layout
talosctl -n 10.0.1.10 disks

# Check LUKS status
talosctl -n 10.0.1.10 read /proc/mounts | grep crypt

# Verify TPM usage
talosctl -n 10.0.1.10 dmesg | grep -i tpm
```

---

## TPM Integration

### 1. TPM Requirements

- TPM 2.0 hardware module
- UEFI firmware with TPM support enabled
- PCR (Platform Configuration Register) measurements

### 2. TPM-Based Disk Encryption

```yaml
machine:
  systemDiskEncryption:
    state:
      provider: luks2
      keys:
        - slot: 0
          tpm:
            # PCRs to bind encryption key
            # PCR 0-7: UEFI and boot sequence
            pcrs:
              - 0  # UEFI firmware
              - 1  # UEFI configuration
              - 2  # Option ROMs
              - 3  # Option ROM configuration
              - 4  # Boot loader
              - 5  # Boot loader configuration
              - 7  # Secure Boot state
```

### 3. Verify TPM Configuration

```bash
# Check TPM presence
talosctl -n 10.0.1.10 read /sys/class/tpm/tpm0/device/description

# View TPM PCR values
talosctl -n 10.0.1.10 dmesg | grep -i "tpm.*pcr"

# Check TPM event log
talosctl -n 10.0.1.10 read /sys/kernel/security/tpm0/binary_bios_measurements
```

---

## KMS Integration for Secret Encryption

### 1. HashiCorp Vault Integration

```yaml
cluster:
  apiServer:
    extraArgs:
      encryption-provider-config: /etc/kubernetes/encryption-config.yaml
    extraVolumes:
      - name: encryption-config
        hostPath: /var/lib/kubernetes/encryption-config.yaml
        mountPath: /etc/kubernetes/encryption-config.yaml
        readonly: true

machine:
  files:
    - path: /var/lib/kubernetes/encryption-config.yaml
      permissions: 0600
      content: |
        apiVersion: apiserver.config.k8s.io/v1
        kind: EncryptionConfiguration
        resources:
          - resources:
              - secrets
            providers:
              - kms:
                  name: vault
                  endpoint: unix:///var/run/kmsplugin/socket.sock
                  cachesize: 1000
                  timeout: 3s
              - identity: {}
```

**Deploy Vault KMS Plugin**:

```yaml
# vault-kms-plugin.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vault-kms-plugin
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: vault-kms-plugin
  template:
    metadata:
      labels:
        app: vault-kms-plugin
    spec:
      hostNetwork: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - effect: NoSchedule
        operator: Exists
      containers:
      - name: vault-kms-plugin
        image: hashicorp/vault-k8s:latest
        args:
        - kms
        - -vault-addr=https://vault.example.com:8200
        - -vault-token-path=/var/run/secrets/vault/token
        env:
        - name: VAULT_CACERT
          value: /var/run/secrets/vault/ca.crt
        volumeMounts:
        - name: kmsplugin
          mountPath: /var/run/kmsplugin
        - name: vault-token
          mountPath: /var/run/secrets/vault
      volumes:
      - name: kmsplugin
        hostPath:
          path: /var/run/kmsplugin
          type: DirectoryOrCreate
      - name: vault-token
        secret:
          secretName: vault-token
```

### 2. AWS KMS Integration

```yaml
cluster:
  apiServer:
    extraArgs:
      encryption-provider-config: /etc/kubernetes/encryption-config.yaml

machine:
  files:
    - path: /var/lib/kubernetes/encryption-config.yaml
      permissions: 0600
      content: |
        apiVersion: apiserver.config.k8s.io/v1
        kind: EncryptionConfiguration
        resources:
          - resources:
              - secrets
            providers:
              - kms:
                  name: aws-kms
                  endpoint: unix:///var/run/kmsplugin/socket.sock
                  cachesize: 1000
                  timeout: 3s
              - identity: {}
```

### 3. Verify Secret Encryption

```bash
# Create test secret
kubectl create secret generic test-secret --from-literal=key=value

# Get secret from etcd (should be encrypted)
talosctl -n 10.0.1.10 etcd get /registry/secrets/default/test-secret

# Should NOT show plaintext "value"
# Should show encrypted blob
```

---

## Kubernetes Audit Policies

### 1. Comprehensive Audit Policy

```yaml
cluster:
  apiServer:
    extraArgs:
      audit-policy-file: /etc/kubernetes/audit-policy.yaml
      audit-log-path: /var/log/kube-apiserver-audit.log
      audit-log-maxage: "30"
      audit-log-maxbackup: "10"
      audit-log-maxsize: "100"
      audit-log-format: json

machine:
  files:
    - path: /var/lib/kubernetes/audit-policy.yaml
      permissions: 0600
      content: |
        apiVersion: audit.k8s.io/v1
        kind: Policy
        omitStages:
          - RequestReceived
        rules:
          # Log admin actions at RequestResponse level
          - level: RequestResponse
            userGroups: ["system:masters"]
            omitStages:
              - RequestReceived

          # Log secret access
          - level: Metadata
            resources:
              - group: ""
                resources: ["secrets"]

          # Log authentication/authorization failures
          - level: Metadata
            omitStages:
              - RequestReceived
            userGroups: ["system:unauthenticated"]

          # Log config changes
          - level: RequestResponse
            verbs: ["create", "update", "patch", "delete"]
            resources:
              - group: ""
                resources: ["configmaps", "serviceaccounts"]
              - group: "rbac.authorization.k8s.io"
                resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

          # Log pod exec/attach
          - level: Metadata
            resources:
              - group: ""
                resources: ["pods/exec", "pods/attach", "pods/portforward"]

          # Log node operations
          - level: RequestResponse
            verbs: ["create", "update", "patch", "delete"]
            resources:
              - group: ""
                resources: ["nodes"]

          # Log persistent volume claims
          - level: Metadata
            resources:
              - group: ""
                resources: ["persistentvolumeclaims"]

          # Log network policy changes
          - level: RequestResponse
            verbs: ["create", "update", "patch", "delete"]
            resources:
              - group: "networking.k8s.io"
                resources: ["networkpolicies"]

          # Catch-all for everything else
          - level: Metadata
            omitStages:
              - RequestReceived
```

### 2. Forward Audit Logs to SIEM

**Falco Integration**:

```bash
# Install Falco for runtime security
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true

# Configure Falco to parse Kubernetes audit logs
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-audit-rules
  namespace: falco
data:
  k8s-audit-rules.yaml: |
    - rule: Unauthorized secret access
      desc: Detect unauthorized access to secrets
      condition: >
        ka.verb in (get, list) and
        ka.target.resource = secrets and
        not ka.user.name in (system:serviceaccount:kube-system:*)
      output: >
        Unauthorized secret access
        (user=%ka.user.name resource=%ka.target.name namespace=%ka.target.namespace)
      priority: WARNING
      source: k8s_audit

    - rule: Privileged pod created
      desc: Detect creation of privileged pods
      condition: >
        ka.verb = create and
        ka.target.resource = pods and
        ka.req.pod.containers.privileged = true
      output: >
        Privileged pod created
        (user=%ka.user.name pod=%ka.target.name namespace=%ka.target.namespace)
      priority: CRITICAL
      source: k8s_audit
EOF
```

---

## Network Security

### 1. Network Segmentation

```yaml
machine:
  network:
    interfaces:
      # Cluster network (pod/service traffic)
      - interface: eth0
        addresses:
          - 10.0.1.10/24
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1

      # Management network (Talos API, restricted)
      - interface: eth1
        addresses:
          - 192.168.1.10/24

      # Storage network (isolated)
      - interface: eth2
        addresses:
          - 172.16.1.10/24

  kubelet:
    nodeIP:
      validSubnets:
        - 10.0.1.0/24  # Only cluster network
```

### 2. Firewall Rules (iptables/nftables at infrastructure)

**Control Plane Nodes**:
```bash
# API Server (6443) - Only from trusted networks
iptables -A INPUT -p tcp --dport 6443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 6443 -j DROP

# Talos API (50000) - Only from management network
iptables -A INPUT -p tcp --dport 50000 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 50000 -j DROP

# etcd (2379-2380) - Only between control plane nodes
iptables -A INPUT -p tcp --dport 2379:2380 -s 10.0.1.10 -j ACCEPT
iptables -A INPUT -p tcp --dport 2379:2380 -s 10.0.1.11 -j ACCEPT
iptables -A INPUT -p tcp --dport 2379:2380 -s 10.0.1.12 -j ACCEPT
iptables -A INPUT -p tcp --dport 2379:2380 -j DROP

# Kubelet (10250) - Only from control plane
iptables -A INPUT -p tcp --dport 10250 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j DROP
```

### 3. Cilium Network Policies

```yaml
# Deny all ingress by default
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  endpointSelector: {}
  ingress:
  - fromEntities:
    - cluster
---
# Allow DNS
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-dns
  namespace: default
spec:
  endpointSelector: {}
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s:k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      - port: "53"
        protocol: TCP
---
# Restrict access to etcd
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: restrict-etcd-access
spec:
  endpointSelector:
    matchLabels:
      component: etcd
  ingress:
  - fromEndpoints:
    - matchLabels:
        component: kube-apiserver
    toPorts:
    - ports:
      - port: "2379"
```

---

## Pod Security Standards

### 1. Enable Pod Security Admission

```yaml
cluster:
  apiServer:
    extraArgs:
      feature-gates: PodSecurity=true
    admissionControl:
      - name: PodSecurity
        configuration:
          apiVersion: pod-security.admission.config.k8s.io/v1
          kind: PodSecurityConfiguration
          defaults:
            enforce: "restricted"
            enforce-version: "latest"
            audit: "restricted"
            audit-version: "latest"
            warn: "restricted"
            warn-version: "latest"
          exemptions:
            usernames: []
            runtimeClasses: []
            namespaces:
              - kube-system
              - calico-system
              - cilium
```

### 2. Namespace-Level Pod Security

```yaml
# Restricted namespace (highest security)
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Baseline namespace (moderate security)
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 3. Kyverno Policy Enforcement

```yaml
# Install Kyverno
kubectl apply -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Example policy: Require non-root containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
spec:
  validationFailureAction: enforce
  rules:
  - name: check-containers
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Containers must run as non-root user"
      pattern:
        spec:
          containers:
          - securityContext:
              runAsNonRoot: true
---
# Disallow privileged containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: enforce
  rules:
  - name: check-privileged
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
```

---

## Certificate Management

### 1. Certificate Rotation

```bash
# View current certificate expiration
talosctl -n 10.0.1.10 get certificates

# Rotate certificates (automatic with proper secrets)
talosctl -n 10.0.1.10 rotate-ca

# Manual certificate renewal
talosctl gen secrets --from-kubernetes-pki /var/lib/secrets/kubernetes.crt
```

### 2. Custom CA Certificates

```yaml
machine:
  ca:
    crt: |
      -----BEGIN CERTIFICATE-----
      <custom-ca-certificate>
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      <custom-ca-key>
      -----END RSA PRIVATE KEY-----
```

### 3. Certificate Monitoring

```yaml
# Deploy cert-manager for certificate monitoring
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create certificate exporter
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: certificate-exporter
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: certificate-exporter
  template:
    metadata:
      labels:
        app: certificate-exporter
    spec:
      hostNetwork: true
      containers:
      - name: exporter
        image: joemiller/x509-certificate-exporter:latest
        args:
        - --watch-dir=/etc/kubernetes/pki
        volumeMounts:
        - name: pki
          mountPath: /etc/kubernetes/pki
          readOnly: true
      volumes:
      - name: pki
        hostPath:
          path: /system/secrets/kubernetes
EOF
```

---

## API Access Control

### 1. Talos API RBAC

```yaml
machine:
  features:
    rbac: true  # Enable RBAC for Talos API (v1.6+)

  # Generate role-based talosconfigs
  certSANs:
    - talos-api.example.com
```

**Create read-only talosconfig**:

```bash
# Generate admin config
talosctl gen config cluster-admin https://10.0.1.100:6443 \
  --with-secrets secrets.yaml

# Generate read-only config (requires custom RBAC setup)
# Note: Full RBAC implementation depends on Talos version
```

### 2. Kubernetes RBAC

```yaml
# Cluster admin role (full access)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: admin@example.com
  apiGroup: rbac.authorization.k8s.io
---
# Namespace admin role (limited to namespace)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: namespace-admin
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: admin
subjects:
- kind: User
  name: developer@example.com
  apiGroup: rbac.authorization.k8s.io
---
# Read-only cluster role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: read-only
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
```

---

## Compliance Frameworks

### 1. CIS Kubernetes Benchmark

```bash
# Install kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# View results
kubectl logs -n kube-bench job/kube-bench

# Key controls for Talos:
# - 1.1.X: Master node configuration files (N/A - immutable OS)
# - 1.2.X: API server settings (configured in machine config)
# - 1.3.X: Controller manager settings
# - 1.4.X: Scheduler settings
# - 4.1.X: Worker node configuration
# - 5.1.X: RBAC and service accounts
```

### 2. PCI-DSS Compliance

**Requirements for Talos**:
- ✅ Requirement 2: Change vendor defaults (custom machine configs)
- ✅ Requirement 3: Protect stored data (disk encryption, KMS)
- ✅ Requirement 6: Secure systems (immutable OS, signed images)
- ✅ Requirement 8: Identify and authenticate (RBAC, certificate-based auth)
- ✅ Requirement 10: Track and monitor (audit logs, Falco)
- ✅ Requirement 11: Test security (regular scanning, penetration testing)

### 3. SOC 2 Compliance

**Key Controls**:

```yaml
# Audit logging (CC6.1)
cluster:
  apiServer:
    extraArgs:
      audit-log-path: /var/log/kube-apiserver-audit.log
      audit-log-maxage: "90"  # 90-day retention

# Access control (CC6.2)
machine:
  features:
    rbac: true

# Encryption (CC6.7)
machine:
  systemDiskEncryption:
    state:
      provider: luks2
      keys:
        - slot: 0
          tpm: {}

# Change management (CC8.1)
# Use GitOps for all machine config changes
# Require PR reviews and approvals
```

---

## Security Monitoring

### 1. Falco Runtime Security

```bash
# Install Falco
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.grpc.enabled=true

# Deploy Falco rules for Talos
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-talos-rules
  namespace: falco
data:
  talos-rules.yaml: |
    - rule: Unauthorized Talos API Access
      desc: Detect unauthorized access to Talos API
      condition: >
        fd.sport=50000 and
        not fd.sip in (192.168.1.0/24)
      output: >
        Unauthorized Talos API access
        (connection=%fd.name user=%user.name)
      priority: CRITICAL
EOF
```

### 2. Prometheus Monitoring

```yaml
# Monitor etcd metrics
- job_name: 'etcd'
  static_configs:
  - targets:
    - 10.0.1.10:2381
    - 10.0.1.11:2381
    - 10.0.1.12:2381

# Monitor kubelet
- job_name: 'kubelet'
  scheme: https
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  kubernetes_sd_configs:
  - role: node
```

---

## Best Practices Summary

### Critical Security Controls

1. **Immutability**: Leverage Talos's immutable OS design
2. **Encryption**: Enable disk encryption (LUKS2) and secrets at rest (KMS)
3. **Secure Boot**: Implement secure boot with custom keys
4. **Network Segmentation**: Separate management, cluster, and storage networks
5. **RBAC**: Implement least-privilege access for both Talos API and Kubernetes
6. **Audit Logging**: Comprehensive audit policies with SIEM integration
7. **Pod Security**: Enforce restricted pod security standards
8. **Certificate Rotation**: Automate certificate lifecycle management
9. **Monitoring**: Real-time security monitoring with Falco and Prometheus
10. **Compliance**: Regular compliance checks (CIS, PCI-DSS, SOC 2)

### Security Checklist

- ✅ Disk encryption enabled (LUKS2 with TPM)
- ✅ Secure boot configured and verified
- ✅ KMS integration for Kubernetes secrets
- ✅ Comprehensive audit policies configured
- ✅ Network segmentation implemented
- ✅ Firewall rules at infrastructure level
- ✅ Pod Security Standards enforced
- ✅ RBAC policies configured (least privilege)
- ✅ Certificate rotation automated
- ✅ Security monitoring (Falco) deployed
- ✅ Compliance scanning (kube-bench) scheduled
- ✅ Vulnerability scanning (Trivy) in CI/CD
- ✅ Regular security audits scheduled
- ✅ Incident response procedures documented
- ✅ Disaster recovery tested quarterly
