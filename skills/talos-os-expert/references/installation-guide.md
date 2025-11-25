# Talos Linux Installation Guide

Complete reference for deploying Talos clusters across different environments with detailed machine configurations and networking setups.

---

## Table of Contents

1. [Bare Metal Installation](#bare-metal-installation)
2. [Cloud Provider Deployments](#cloud-provider-deployments)
3. [Network Configuration Patterns](#network-configuration-patterns)
4. [Storage Configuration](#storage-configuration)
5. [CNI Installation](#cni-installation)
6. [etcd Configuration](#etcd-configuration)
7. [Multi-Cluster Setup](#multi-cluster-setup)

---

## Bare Metal Installation

### 1. Prerequisites

**Hardware Requirements**:
- Control Plane: 2 CPU, 4GB RAM, 120GB SSD (minimum)
- Worker Nodes: 2 CPU, 8GB RAM, 120GB SSD (minimum)
- TPM 2.0 (optional, for disk encryption)
- UEFI firmware (for secure boot)

**Network Requirements**:
- Static IP addresses or DHCP reservations
- Layer 2 connectivity between all nodes
- Internet access for pulling images (or air-gapped setup)
- VIP or load balancer for control plane HA

### 2. Create Bootable Media

```bash
# Download Talos ISO
wget https://github.com/siderolabs/talos/releases/download/v1.6.0/metal-amd64.iso

# Or use PXE boot
wget https://github.com/siderolabs/talos/releases/download/v1.6.0/kernel-amd64
wget https://github.com/siderolabs/talos/releases/download/v1.6.0/initramfs-amd64.xz

# Write ISO to USB
dd if=metal-amd64.iso of=/dev/sdX bs=4M status=progress
```

### 3. Boot Nodes into Maintenance Mode

Boot all nodes from Talos ISO/PXE. Nodes will start in maintenance mode waiting for configuration.

```bash
# Get node IPs in maintenance mode
talosctl -n <node-ip> version --insecure
```

### 4. Generate Cluster Configuration

```bash
# Create directory structure
mkdir -p talos-cluster/{configs,patches,secrets}
cd talos-cluster

# Generate base configuration
talosctl gen config talos-prod-cluster https://10.0.1.100:6443 \
  --with-secrets secrets/secrets.yaml \
  --output configs/

# This creates:
# - configs/controlplane.yaml
# - configs/worker.yaml
# - configs/talosconfig
# - secrets/secrets.yaml (save this securely!)
```

### 5. Create Machine Config Patches

**Control Plane Patch** (`patches/controlplane.yaml`):

```yaml
machine:
  network:
    hostname: cp-01  # Update per node
    interfaces:
      - interface: eth0
        dhcp: false
        addresses:
          - 10.0.1.10/24  # Update per node
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1
        vip:
          ip: 10.0.1.100  # Virtual IP for HA
    nameservers:
      - 8.8.8.8
      - 1.1.1.1
    timeServers:
      - time.cloudflare.com

  install:
    disk: /dev/sda
    image: ghcr.io/siderolabs/installer:v1.6.0
    wipe: false
    diskSelector:
      size: '>= 100GB'
      type: ssd

  kubelet:
    image: ghcr.io/siderolabs/kubelet:v1.29.1
    extraArgs:
      feature-gates: GracefulNodeShutdown=true
      rotate-server-certificates: true
    nodeIP:
      validSubnets:
        - 10.0.1.0/24

  certSANs:
    - 10.0.1.100  # VIP
    - 10.0.1.10   # Node IP
    - 10.0.1.11
    - 10.0.1.12
    - cp.talos.local

cluster:
  allowSchedulingOnControlPlanes: false  # Don't schedule workloads on control plane

  network:
    cni:
      name: none  # Install CNI manually
    dnsDomain: cluster.local
    podSubnets:
      - 10.244.0.0/16
    serviceSubnets:
      - 10.96.0.0/12

  apiServer:
    certSANs:
      - 10.0.1.100
      - cp.talos.local
    extraArgs:
      audit-log-path: /var/log/kube-apiserver-audit.log
      audit-log-maxage: "30"
      audit-log-maxbackup: "10"
      audit-log-maxsize: "100"
      feature-gates: ServerSideApply=true

  controllerManager:
    extraArgs:
      bind-address: 0.0.0.0
      node-cidr-mask-size: "24"

  scheduler:
    extraArgs:
      bind-address: 0.0.0.0

  etcd:
    extraArgs:
      listen-metrics-urls: http://0.0.0.0:2381
      quota-backend-bytes: "8589934592"  # 8GB
      auto-compaction-retention: "1000"
      snapshot-count: "10000"
      max-snapshots: "5"
      max-wals: "5"
```

**Worker Patch** (`patches/worker.yaml`):

```yaml
machine:
  network:
    hostname: worker-01  # Update per node
    interfaces:
      - interface: eth0
        dhcp: false
        addresses:
          - 10.0.1.20/24  # Update per node
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1
    nameservers:
      - 8.8.8.8
      - 1.1.1.1
    timeServers:
      - time.cloudflare.com

  install:
    disk: /dev/sda
    image: ghcr.io/siderolabs/installer:v1.6.0
    wipe: false

  kubelet:
    extraArgs:
      rotate-server-certificates: true
      max-pods: "110"
    nodeIP:
      validSubnets:
        - 10.0.1.0/24
```

### 6. Apply Configurations

```bash
# Generate patched configs for each node
talosctl gen config talos-prod-cluster https://10.0.1.100:6443 \
  --with-secrets secrets/secrets.yaml \
  --config-patch-control-plane @patches/controlplane.yaml \
  --config-patch-worker @patches/worker.yaml

# Customize hostname/IP for each control plane node
cat > patches/cp-01.yaml <<EOF
machine:
  network:
    hostname: cp-01
    interfaces:
      - interface: eth0
        addresses:
          - 10.0.1.10/24
EOF

# Apply to first control plane node
talosctl apply-config --insecure \
  --nodes 10.0.1.10 \
  --file controlplane.yaml \
  --config-patch @patches/cp-01.yaml

# Wait for node to boot
sleep 30

# Set environment for talosctl
export TALOSCONFIG=configs/talosconfig
talosctl config endpoint 10.0.1.10
talosctl config node 10.0.1.10

# Bootstrap etcd (ONLY ONCE!)
talosctl bootstrap

# Wait for etcd to be healthy
talosctl -n 10.0.1.10 service etcd status

# Apply to second control plane node
cat > patches/cp-02.yaml <<EOF
machine:
  network:
    hostname: cp-02
    interfaces:
      - interface: eth0
        addresses:
          - 10.0.1.11/24
EOF

talosctl apply-config --insecure \
  --nodes 10.0.1.11 \
  --file controlplane.yaml \
  --config-patch @patches/cp-02.yaml

# Apply to third control plane node
cat > patches/cp-03.yaml <<EOF
machine:
  network:
    hostname: cp-03
    interfaces:
      - interface: eth0
        addresses:
          - 10.0.1.12/24
EOF

talosctl apply-config --insecure \
  --nodes 10.0.1.12 \
  --file controlplane.yaml \
  --config-patch @patches/cp-03.yaml

# Verify etcd cluster
talosctl -n 10.0.1.10,10.0.1.11,10.0.1.12 etcd members

# Apply to worker nodes
for i in {1..3}; do
  ip="10.0.1.2$i"
  cat > patches/worker-0$i.yaml <<EOF
machine:
  network:
    hostname: worker-0$i
    interfaces:
      - interface: eth0
        addresses:
          - $ip/24
EOF

  talosctl apply-config --insecure \
    --nodes $ip \
    --file worker.yaml \
    --config-patch @patches/worker-0$i.yaml
done

# Retrieve kubeconfig
talosctl kubeconfig --nodes 10.0.1.10 --force

# Verify cluster
kubectl get nodes
kubectl get pods -A
```

---

## Cloud Provider Deployments

### AWS Deployment

```bash
# Install Talos on EC2 instances
# Use AMI: ami-0a1b2c3d4e5f6g7h8 (check Talos GitHub for latest)

# Generate cloud-specific configuration
talosctl gen config talos-aws-cluster \
  https://talos-elb-123456.us-east-1.elb.amazonaws.com:6443 \
  --with-secrets secrets/aws-secrets.yaml

# Create AWS-specific patch
cat > patches/aws.yaml <<EOF
machine:
  install:
    disk: /dev/nvme0n1  # AWS NVMe disk
    image: ghcr.io/siderolabs/installer:v1.6.0

  kubelet:
    cloudProvider:
      enabled: true
      name: aws

  network:
    interfaces:
      - interface: eth0
        dhcp: true
        vip:
          ip: 10.0.1.100  # If using VIP

cluster:
  network:
    cni:
      name: custom
      urls:
        - https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/aws-k8s-cni.yaml

  apiServer:
    certSANs:
      - talos-elb-123456.us-east-1.elb.amazonaws.com
    extraArgs:
      cloud-provider: aws

  controllerManager:
    extraArgs:
      cloud-provider: aws
EOF

# Apply to instances
for instance_ip in 10.0.1.10 10.0.1.11 10.0.1.12; do
  talosctl apply-config --insecure \
    --nodes $instance_ip \
    --file controlplane.yaml \
    --config-patch @patches/aws.yaml
done
```

### Google Cloud Platform (GCP)

```bash
# GCP-specific patch
cat > patches/gcp.yaml <<EOF
machine:
  install:
    disk: /dev/sda  # GCP persistent disk

  kubelet:
    cloudProvider:
      enabled: true
      name: gce

  network:
    interfaces:
      - interface: eth0
        dhcp: true

cluster:
  network:
    cni:
      name: custom
      urls:
        - https://raw.githubusercontent.com/cilium/cilium/v1.14/install/kubernetes/quick-install.yaml

  apiServer:
    certSANs:
      - 35.123.45.67  # Load balancer IP
    extraArgs:
      cloud-provider: gce

  controllerManager:
    extraArgs:
      cloud-provider: gce
EOF
```

### Azure Deployment

```bash
# Azure-specific patch
cat > patches/azure.yaml <<EOF
machine:
  install:
    disk: /dev/sda

  kubelet:
    cloudProvider:
      enabled: true
      name: azure

  network:
    interfaces:
      - interface: eth0
        dhcp: true

cluster:
  apiServer:
    extraArgs:
      cloud-provider: azure
      cloud-config: /etc/kubernetes/azure.json

  controllerManager:
    extraArgs:
      cloud-provider: azure
      cloud-config: /etc/kubernetes/azure.json

  files:
    - path: /etc/kubernetes/azure.json
      permissions: 0644
      content: |
        {
          "cloud": "AzurePublicCloud",
          "tenantId": "your-tenant-id",
          "subscriptionId": "your-subscription-id",
          "resourceGroup": "your-resource-group",
          "location": "eastus",
          "vnetName": "your-vnet",
          "subnetName": "your-subnet"
        }
EOF
```

---

## Network Configuration Patterns

### Pattern 1: Bonded Interfaces for Redundancy

```yaml
machine:
  network:
    interfaces:
      # Bond configuration
      - interface: bond0
        dhcp: false
        addresses:
          - 10.0.1.10/24
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1
        bond:
          mode: 802.3ad  # LACP
          lacpRate: fast
          miimon: 100
          updelay: 200
          downdelay: 200
          interfaces:
            - eth0
            - eth1

      # Individual interfaces (enslaved to bond)
      - interface: eth0
        dhcp: false
      - interface: eth1
        dhcp: false
```

### Pattern 2: VLAN Configuration

```yaml
machine:
  network:
    interfaces:
      # Parent interface
      - interface: eth0
        dhcp: false

      # VLAN 100 - Management
      - interface: eth0.100
        dhcp: false
        addresses:
          - 192.168.100.10/24
        vlanId: 100

      # VLAN 200 - Cluster
      - interface: eth0.200
        dhcp: false
        addresses:
          - 10.0.1.10/24
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1
        vlanId: 200

  kubelet:
    nodeIP:
      validSubnets:
        - 10.0.1.0/24  # Force kubelet to use cluster VLAN
```

### Pattern 3: Dual-Stack IPv4/IPv6

```yaml
machine:
  network:
    interfaces:
      - interface: eth0
        dhcp: false
        addresses:
          - 10.0.1.10/24
          - 2001:db8:1::10/64
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1
          - network: ::/0
            gateway: 2001:db8:1::1

cluster:
  network:
    podSubnets:
      - 10.244.0.0/16
      - 2001:db8:42:0::/56
    serviceSubnets:
      - 10.96.0.0/12
      - 2001:db8:42:1::/112
```

### Pattern 4: Multiple NICs for Network Segmentation

```yaml
machine:
  network:
    interfaces:
      # eth0 - Cluster network
      - interface: eth0
        dhcp: false
        addresses:
          - 10.0.1.10/24
        routes:
          - network: 0.0.0.0/0
            gateway: 10.0.1.1

      # eth1 - Management network (Talos API)
      - interface: eth1
        dhcp: false
        addresses:
          - 192.168.1.10/24

      # eth2 - Storage network
      - interface: eth2
        dhcp: false
        addresses:
          - 172.16.1.10/24

  kubelet:
    nodeIP:
      validSubnets:
        - 10.0.1.0/24  # Kubelet uses cluster network only
```

---

## Storage Configuration

### Pattern 1: Local Path Provisioner

```yaml
# Deploy local-path-provisioner
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml

# Set as default storage class
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

### Pattern 2: Longhorn Distributed Storage

```bash
# Install Longhorn
kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/v1.5.3/deploy/longhorn.yaml

# Verify installation
kubectl -n longhorn-system get pods

# Access UI
kubectl -n longhorn-system port-forward svc/longhorn-frontend 8080:80
```

**Machine config for Longhorn requirements**:

```yaml
machine:
  install:
    disk: /dev/sda
    extraKernelArgs:
      - cgroup_enable=memory
      - cgroup_memory=1

  sysctls:
    vm.max_map_count: "262144"

  files:
    - path: /var/lib/longhorn
      op: create
      permissions: 0755
```

### Pattern 3: Rook-Ceph

```yaml
machine:
  disks:
    # Additional disks for Ceph OSDs
    - device: /dev/sdb
      partitions:
        - mountpoint: /var/lib/rook
    - device: /dev/sdc
      partitions:
        - mountpoint: /var/lib/rook/osd1

  kubelet:
    extraMounts:
      - destination: /var/lib/rook
        type: bind
        source: /var/lib/rook
        options:
          - bind
          - rshared
          - rw
```

---

## CNI Installation

### Cilium (Recommended for Security)

```bash
# Install Cilium CLI
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz
tar xzvf cilium-linux-amd64.tar.gz
sudo mv cilium /usr/local/bin/

# Install Cilium
cilium install \
  --version 1.14.5 \
  --set ipam.mode=kubernetes \
  --set kubeProxyReplacement=strict \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true

# Verify installation
cilium status --wait

# Enable Hubble (observability)
cilium hubble enable --ui

# Test connectivity
cilium connectivity test
```

**Machine config for Cilium**:

```yaml
cluster:
  network:
    cni:
      name: none  # Install Cilium manually

  proxy:
    disabled: true  # Cilium replaces kube-proxy
```

### Flannel (Simple, Lightweight)

```yaml
cluster:
  network:
    cni:
      name: custom
      urls:
        - https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
```

### Calico (Network Policy)

```yaml
cluster:
  network:
    cni:
      name: custom
      urls:
        - https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

---

## etcd Configuration

### High-Performance etcd Settings

```yaml
cluster:
  etcd:
    extraArgs:
      # Increase quota to 8GB
      quota-backend-bytes: "8589934592"

      # Performance tuning
      heartbeat-interval: "100"
      election-timeout: "1000"

      # Snapshot settings
      snapshot-count: "10000"
      max-snapshots: "5"
      max-wals: "5"

      # Compaction
      auto-compaction-mode: revision
      auto-compaction-retention: "1000"

      # Metrics
      listen-metrics-urls: http://0.0.0.0:2381

      # Logging
      log-level: info

    # Advertise on specific interface
    advertisedSubnets:
      - 10.0.1.0/24
```

### etcd Backup Configuration

```bash
# Manual snapshot
talosctl -n 10.0.1.10 etcd snapshot /tmp/etcd-backup.db

# Retrieve snapshot
talosctl -n 10.0.1.10 cp /tmp/etcd-backup.db ./etcd-backup-$(date +%Y%m%d-%H%M%S).db

# Automated backup with CronJob
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: etcd-backup
  namespace: kube-system
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          hostNetwork: true
          containers:
          - name: etcd-backup
            image: gcr.io/etcd-development/etcd:v3.5.11
            command:
            - /bin/sh
            - -c
            - |
              ETCDCTL_API=3 etcdctl \
                --endpoints=https://127.0.0.1:2379 \
                --cacert=/etc/kubernetes/pki/etcd/ca.crt \
                --cert=/etc/kubernetes/pki/etcd/server.crt \
                --key=/etc/kubernetes/pki/etcd/server.key \
                snapshot save /backup/etcd-snapshot-\$(date +%Y%m%d-%H%M%S).db
            volumeMounts:
            - name: etcd-certs
              mountPath: /etc/kubernetes/pki/etcd
              readOnly: true
            - name: backup
              mountPath: /backup
          volumes:
          - name: etcd-certs
            hostPath:
              path: /system/secrets/kubernetes/etcd
          - name: backup
            hostPath:
              path: /var/lib/etcd-backups
          restartPolicy: OnFailure
          nodeSelector:
            node-role.kubernetes.io/control-plane: ""
          tolerations:
          - effect: NoSchedule
            operator: Exists
EOF
```

---

## Multi-Cluster Setup

### Hub and Spoke Architecture

**Hub Cluster** (Management):

```yaml
# patches/hub-cluster.yaml
machine:
  network:
    hostname: hub-cp-01

cluster:
  clusterName: hub-cluster
  allowSchedulingOnControlPlanes: true  # Hub cluster can schedule workloads

  apiServer:
    certSANs:
      - hub.example.com
      - 10.100.1.100
```

**Spoke Clusters** (Workloads):

```yaml
# patches/spoke-us-east.yaml
cluster:
  clusterName: spoke-us-east
  externalCloudProvider:
    enabled: true
    manifests:
      - https://raw.githubusercontent.com/kubernetes/cloud-provider-aws/master/manifests/rbac.yaml
```

### Multi-Cluster talosctl Configuration

```bash
# Generate configs for each cluster
talosctl gen config hub-cluster https://hub.example.com:6443 \
  --with-secrets secrets/hub-secrets.yaml \
  --output-types talosconfig \
  -o talosconfig-hub

talosctl gen config spoke-us-east https://spoke-us-east.example.com:6443 \
  --with-secrets secrets/spoke-us-east-secrets.yaml \
  --output-types talosconfig \
  -o talosconfig-spoke-us-east

talosctl gen config spoke-eu-west https://spoke-eu-west.example.com:6443 \
  --with-secrets secrets/spoke-eu-west-secrets.yaml \
  --output-types talosconfig \
  -o talosconfig-spoke-eu-west

# Merge all configs
talosctl config merge talosconfig-hub
talosctl config merge talosconfig-spoke-us-east
talosctl config merge talosconfig-spoke-eu-west

# List contexts
talosctl config contexts

# Switch between clusters
talosctl config context hub-cluster
talosctl config context spoke-us-east
talosctl config context spoke-eu-west
```

---

## Advanced Installation Scenarios

### Air-Gapped Installation

```bash
# 1. Download all required images on internet-connected machine
docker pull ghcr.io/siderolabs/installer:v1.6.0
docker pull ghcr.io/siderolabs/kubelet:v1.29.1
docker pull registry.k8s.io/kube-apiserver:v1.29.1
docker pull registry.k8s.io/kube-controller-manager:v1.29.1
docker pull registry.k8s.io/kube-scheduler:v1.29.1
docker pull registry.k8s.io/kube-proxy:v1.29.1
docker pull registry.k8s.io/pause:3.9
docker pull registry.k8s.io/coredns/coredns:v1.11.1
docker pull registry.k8s.io/etcd:3.5.11-0

# 2. Save images to tar files
docker save ghcr.io/siderolabs/installer:v1.6.0 -o talos-installer.tar
docker save <all-other-images> -o k8s-images.tar

# 3. Set up local registry on air-gapped network
docker run -d -p 5000:5000 --restart=always --name registry registry:2

# 4. Load and push images
docker load -i talos-installer.tar
docker tag ghcr.io/siderolabs/installer:v1.6.0 registry.local:5000/installer:v1.6.0
docker push registry.local:5000/installer:v1.6.0

# 5. Configure Talos to use local registry
cat > patches/airgap.yaml <<EOF
machine:
  install:
    image: registry.local:5000/installer:v1.6.0

  registries:
    mirrors:
      docker.io:
        endpoints:
          - http://registry.local:5000
      k8s.gcr.io:
        endpoints:
          - http://registry.local:5000
      ghcr.io:
        endpoints:
          - http://registry.local:5000
EOF
```

### Raspberry Pi Installation

```bash
# Download ARM64 image
wget https://github.com/siderolabs/talos/releases/download/v1.6.0/metal-rpi_generic-arm64.img.xz

# Write to SD card
xzcat metal-rpi_generic-arm64.img.xz | dd of=/dev/sdX bs=4M status=progress

# Generate config with ARM-specific settings
cat > patches/rpi.yaml <<EOF
machine:
  install:
    disk: /dev/mmcblk0
    image: ghcr.io/siderolabs/installer:v1.6.0

  kubelet:
    extraArgs:
      eviction-hard: memory.available<5%
      eviction-soft: memory.available<10%
EOF
```

---

## Troubleshooting Installation Issues

### Issue 1: Node Not Booting

```bash
# Check BIOS/UEFI settings
# - Ensure UEFI boot is enabled
# - Check boot order
# - Disable secure boot (unless using custom keys)

# View boot logs via console or IPMI
talosctl -n <node-ip> dmesg --insecure
```

### Issue 2: Network Configuration Not Applied

```bash
# Verify interface names
talosctl -n <node-ip> get links --insecure

# Check network configuration
talosctl -n <node-ip> get addresses --insecure
talosctl -n <node-ip> get routes --insecure

# Test connectivity
talosctl -n <node-ip> netstat --insecure
```

### Issue 3: etcd Won't Bootstrap

```bash
# Check etcd service status
talosctl -n 10.0.1.10 service etcd status

# View etcd logs
talosctl -n 10.0.1.10 logs etcd

# Common causes:
# - Incorrect time (NTP not synced)
# - Network connectivity issues
# - Bootstrap run multiple times
# - Insufficient disk space
```

### Issue 4: Unable to Join Worker Nodes

```bash
# Verify control plane is healthy
talosctl -n 10.0.1.10 health

# Check worker can reach control plane
talosctl -n 10.0.1.20 netstat --tcp --listening

# Verify machine config has correct control plane endpoint
talosctl -n 10.0.1.20 get machineconfig -o yaml | grep -A 5 controlPlane
```

---

## Post-Installation Checklist

- ✅ All nodes are in `Ready` state
- ✅ etcd cluster is healthy (3+ members)
- ✅ All system pods are running
- ✅ CNI is installed and functional
- ✅ DNS resolution works (test with `nslookup kubernetes.default`)
- ✅ Talos API accessible from management workstation
- ✅ kubeconfig retrieved and working
- ✅ Secrets backup stored securely (encrypted)
- ✅ Machine configs version controlled in Git
- ✅ Monitoring and logging configured
- ✅ Backup strategy implemented (etcd snapshots)
- ✅ Disaster recovery procedures documented

---

## Best Practices

1. **Always save secrets**: Use `--with-secrets` flag during config generation
2. **Version control configs**: Store all machine configs in Git with encryption (SOPS, age)
3. **Test in staging**: Deploy to staging environment before production
4. **Use static IPs**: Avoid DHCP for control plane nodes
5. **Implement HA**: Minimum 3 control plane nodes for production
6. **Automate backups**: Schedule regular etcd snapshots
7. **Document network topology**: Maintain diagrams of network architecture
8. **Validate before apply**: Always use `talosctl validate` before applying configs
9. **Monitor from day one**: Set up Prometheus/Grafana during initial deployment
10. **Plan for upgrades**: Test upgrade procedures in staging before production
