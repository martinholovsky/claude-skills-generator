# Cilium Network Policies - Comprehensive Guide

This document provides detailed examples and patterns for Cilium network policies across L3/L4/L7, DNS-based filtering, and advanced security scenarios.

## Table of Contents

1. [L3/L4 Network Policies](#l3l4-network-policies)
2. [L7 Application-Layer Policies](#l7-application-layer-policies)
3. [DNS and FQDN-Based Policies](#dns-and-fqdn-based-policies)
4. [Deny Policies](#deny-policies)
5. [Advanced Policy Patterns](#advanced-policy-patterns)
6. [Policy Troubleshooting](#policy-troubleshooting)

---

## L3/L4 Network Policies

### Basic L3 (IP-based) Policies

**Allow traffic from specific CIDR blocks:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-from-cidr
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: database
  ingress:
  - fromCIDR:
    - 10.0.0.0/16  # Internal network
    - 172.16.0.0/12  # VPC CIDR
  - fromCIDRSet:
    - cidr: 192.168.0.0/16
      except:
      - 192.168.100.0/24  # Exclude specific subnet
```

**Egress to external IPs:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-external-api
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: worker
  egress:
  - toCIDR:
    - 203.0.113.0/24  # External API CIDR
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

### L4 Port-Based Policies

**Restrict traffic by port and protocol:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: multi-port-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: web-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        role: frontend
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443"
        protocol: TCP
      - port: "8080"
        protocol: TCP
  - fromEndpoints:
    - matchLabels:
        role: monitoring
    toPorts:
    - ports:
      - port: "9090"  # Metrics
        protocol: TCP
```

**Port ranges:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: port-range-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: game-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: game-client
    toPorts:
    - ports:
      - port: "7000"
        endPort: "7999"  # Port range 7000-7999
        protocol: TCP
```

### Identity-Based Policies

**Pod-to-pod communication with labels:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: service-to-service
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      tier: backend
      version: v2
  ingress:
  - fromEndpoints:
    - matchLabels:
        tier: frontend
        env: production
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  egress:
  - toEndpoints:
    - matchLabels:
        tier: database
        env: production
    toPorts:
    - ports:
      - port: "5432"
        protocol: TCP
```

**Cross-namespace policies:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cross-namespace
  namespace: app-namespace
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
  # Allow from same namespace
  - fromEndpoints:
    - matchLabels:
        app: frontend
        io.kubernetes.pod.namespace: app-namespace
  # Allow from specific other namespace
  - fromEndpoints:
    - matchLabels:
        app: admin-panel
        io.kubernetes.pod.namespace: admin-namespace
  egress:
  # Access shared services in shared-services namespace
  - toEndpoints:
    - matchLabels:
        app: redis
        io.kubernetes.pod.namespace: shared-services
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
```

### Entity-Based Policies

**Using Cilium entities:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: entity-based
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEntities:
    - cluster  # Any pod in the cluster
  egress:
  # Allow DNS
  - toEntities:
    - kube-dns
  # Allow Kubernetes API
  - toEntities:
    - kube-apiserver
  # Block internet
  - toEntities:
    - cluster  # Only cluster traffic
  # Explicit allow to internet (if needed)
  - toEntities:
    - world  # Internet traffic
    toFQDNs:
    - matchName: "api.stripe.com"
```

**Available entities:**
- `all`: All traffic
- `world`: Outside the cluster
- `cluster`: Within the cluster
- `host`: Host networking
- `remote-node`: Other cluster nodes
- `kube-apiserver`: Kubernetes API server
- `init`: Init identity (before pod starts)
- `health`: Cilium health checks
- `unmanaged`: Non-Cilium managed endpoints
- `none`: No entity

---

## L7 Application-Layer Policies

### HTTP Policies

**Basic HTTP method and path filtering:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-api-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: rest-api
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: web-frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        # GET requests to /api/users/*
        - method: "GET"
          path: "/api/users/.*"
        # POST to /api/users (create user)
        - method: "POST"
          path: "/api/users$"
        # PUT/PATCH to /api/users/:id (update user)
        - method: "PUT|PATCH"
          path: "/api/users/[0-9]+"
        # DELETE to /api/users/:id (admin only, checked elsewhere)
        - method: "DELETE"
          path: "/api/users/[0-9]+"
```

**HTTP header-based filtering:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-headers-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-gateway
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: mobile-app
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
      rules:
        http:
        # Require API key header
        - method: "GET|POST"
          path: "/api/v1/.*"
          headers:
          - "X-API-Key: .*"  # Must have API key
          - "Content-Type: application/json"
        # Require specific User-Agent
        - method: "GET"
          path: "/health"
          headers:
          - "User-Agent: HealthCheck/.*"
```

**HTTP host-based routing:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-host-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: ingress-backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: ingress-controller
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        # API subdomain
        - method: "GET|POST"
          path: "/.*"
          headers:
          - "Host: api\\.example\\.com"
        # Admin subdomain (restrict methods)
        - method: "GET"
          path: "/.*"
          headers:
          - "Host: admin\\.example\\.com"
```

### gRPC Policies

**gRPC service and method filtering:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: grpc-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: grpc-service
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: grpc-client
    toPorts:
    - ports:
      - port: "50051"
        protocol: TCP
      rules:
        # gRPC uses HTTP/2
        http:
        # Allow specific gRPC methods
        - method: "POST"
          path: "/mycompany\\.userservice\\.v1\\.UserService/GetUser"
        - method: "POST"
          path: "/mycompany\\.userservice\\.v1\\.UserService/ListUsers"
        # Deny destructive operations
        # (use ingressDeny for explicit deny)
```

**gRPC with headers (metadata):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: grpc-auth-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: auth-grpc-service
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: authenticated-client
    toPorts:
    - ports:
      - port: "50051"
        protocol: TCP
      rules:
        http:
        - method: "POST"
          path: "/.*"
          headers:
          - "authorization: Bearer .*"  # Require JWT token
          - "x-request-id: .*"  # Require request ID for tracing
```

### Kafka Policies

**Kafka topic-level policies:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: kafka-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: kafka-broker
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: order-service
    toPorts:
    - ports:
      - port: "9092"
        protocol: TCP
      rules:
        kafka:
        # Allow produce to specific topics
        - role: "produce"
          topic: "orders"
        - role: "produce"
          topic: "order-events"
  - fromEndpoints:
    - matchLabels:
        app: analytics-service
    toPorts:
    - ports:
      - port: "9092"
        protocol: TCP
      rules:
        kafka:
        # Allow consume from specific topics
        - role: "consume"
          topic: "orders"
          clientID: "analytics-consumer-.*"
```

**Kafka with API key filtering:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: kafka-apikey-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: kafka-broker
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: payment-service
    toPorts:
    - ports:
      - port: "9092"
        protocol: TCP
      rules:
        kafka:
        - apiVersion: "0|1|2"  # Kafka API versions
          apiKey: "produce"  # Produce API key
          topic: "payment-events"
```

---

## DNS and FQDN-Based Policies

### Basic FQDN Policies

**Allow egress to specific domains:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: fqdn-egress
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-client
  egress:
  # Exact domain match
  - toFQDNs:
    - matchName: "api.github.com"
    - matchName: "api.stripe.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # Pattern matching (wildcards)
  - toFQDNs:
    - matchPattern: "*.amazonaws.com"
    - matchPattern: "*.cloudfront.net"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # Allow DNS resolution
  - toEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
```

### DNS-Based Policies

**Restrict DNS queries:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: dns-filtering
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: restricted-app
  egress:
  # Allow DNS only for approved domains
  - toEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      rules:
        dns:
        # Only allow queries for these patterns
        - matchPattern: "*.example.com"
        - matchPattern: "*.stripe.com"
        - matchName: "api.github.com"
  # Allow HTTPS to resolved domains
  - toFQDNs:
    - matchPattern: "*.example.com"
    - matchPattern: "*.stripe.com"
    - matchName: "api.github.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

**DNS security - block malicious domains:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: dns-security
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: web-app
  egress:
  # Allow DNS
  - toEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
  egressDeny:
  # Block known malicious domains
  - toFQDNs:
    - matchPattern: "*.malware-domain.com"
    - matchPattern: "*.phishing-site.net"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

### Advanced FQDN Patterns

**Multi-cloud egress (AWS, GCP, Azure):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: multi-cloud-egress
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: cloud-integration
  egress:
  # AWS services
  - toFQDNs:
    - matchPattern: "*.amazonaws.com"
    - matchPattern: "*.aws.amazon.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # GCP services
  - toFQDNs:
    - matchPattern: "*.googleapis.com"
    - matchPattern: "*.gcp.google.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # Azure services
  - toFQDNs:
    - matchPattern: "*.azure.com"
    - matchPattern: "*.windows.net"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # DNS
  - toEntities:
    - kube-dns
```

**TTL-aware FQDN policies:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: ttl-aware-fqdn
  namespace: production
  annotations:
    # Cilium respects DNS TTL by default
    # Force minimum TTL (seconds)
    cilium.io/dns-min-ttl: "300"  # 5 minutes
spec:
  endpointSelector:
    matchLabels:
      app: dynamic-backend-client
  egress:
  # Domains with dynamic IPs (CDNs, load balancers)
  - toFQDNs:
    - matchName: "cdn.example.com"  # IP changes frequently
    - matchPattern: "*.cloudfront.net"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

---

## Deny Policies

### Explicit Deny Rules

**Deny specific traffic:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: explicit-deny
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: web-app
  ingressDeny:
  # Deny from untrusted namespace
  - fromEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: untrusted
  egressDeny:
  # Deny access to internal admin services
  - toEndpoints:
    - matchLabels:
        role: admin
        tier: management
  # Deny external social media sites
  - toFQDNs:
    - matchPattern: "*.facebook.com"
    - matchPattern: "*.twitter.com"
```

### Deny Precedence

**Deny overrides allow:**

```yaml
# Allow policy
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-general
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: database
  ingress:
  - fromEndpoints:
    - matchLabels:
        tier: backend
---
# Deny policy (takes precedence)
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-specific
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: database
  ingressDeny:
  - fromEndpoints:
    - matchLabels:
        tier: backend
        env: development  # Deny from dev even though allowed above
```

---

## Advanced Policy Patterns

### Policy Priority and Ordering

**Cluster-wide vs namespace policies:**

```yaml
# Cluster-wide baseline policy
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: baseline-deny
spec:
  endpointSelector: {}
  ingress: []
  egress:
  - toEntities:
    - kube-dns
  - toEntities:
    - kube-apiserver
---
# Namespace-specific allow (overrides cluster-wide for this namespace)
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: namespace-allow
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
```

### Node-Level Policies

**Host firewall (protect nodes):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: node-firewall
spec:
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/worker: ""
  ingress:
  # SSH from bastion only
  - fromCIDR:
    - 10.0.1.0/24  # Bastion CIDR
    toPorts:
    - ports:
      - port: "22"
        protocol: TCP
  # Kubelet from API server
  - fromEntities:
    - kube-apiserver
    toPorts:
    - ports:
      - port: "10250"
        protocol: TCP
  # Monitoring
  - fromEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: monitoring
        k8s:app: prometheus
    toPorts:
    - ports:
      - port: "9100"  # Node exporter
        protocol: TCP
```

### Service-Level Policies

**Target Kubernetes services:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: service-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  # Target service by name (not pods directly)
  - toServices:
    - k8sService:
        serviceName: backend-service
        namespace: production
  # Or target multiple services
  - toServices:
    - k8sService:
        serviceName: redis
        namespace: shared-services
    - k8sService:
        serviceName: postgresql
        namespace: shared-services
```

### Policy for External Workloads

**Allow external (non-Kubernetes) workloads:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: external-workload-access
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
  # Allow from external VMs (registered as CiliumExternalWorkload)
  - fromEndpoints:
    - matchLabels:
        cilium.io/external-workload: "true"
        env: production
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
```

---

## Policy Troubleshooting

### Audit Mode

**Test policies without enforcing:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-policy
  namespace: production
  annotations:
    cilium.io/policy-audit-mode: "true"  # Log but don't enforce
spec:
  endpointSelector:
    matchLabels:
      app: test-app
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: allowed-client
```

**Check audit logs:**

```bash
# Watch for audit verdicts
hubble observe --verdict AUDIT --namespace production

# Check what would be denied
hubble observe --verdict AUDIT --type drop
```

### Policy Verification

**Check applied policies:**

```bash
# List policies in namespace
kubectl get ciliumnetworkpolicies -n production

# Describe specific policy
kubectl describe ciliumnetworkpolicy frontend-policy -n production

# Check policy status
kubectl get cnp frontend-policy -n production -o yaml

# View policy enforcement on endpoint
kubectl exec -n kube-system ds/cilium -- cilium endpoint list
```

### Common Issues

**Issue 1: DNS not allowed**

```yaml
# WRONG: No DNS egress
spec:
  endpointSelector:
    matchLabels:
      app: myapp
  egress: []

# CORRECT: Always allow DNS
spec:
  endpointSelector:
    matchLabels:
      app: myapp
  egress:
  - toEndpoints:
    - matchLabels:
        k8s-app: kube-dns
        io.kubernetes.pod.namespace: kube-system
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
```

**Issue 2: Forgot kube-apiserver access**

```yaml
# CORRECT: Allow API server
egress:
- toEntities:
  - kube-apiserver
```

**Issue 3: Label selector mismatch**

```bash
# Verify pod labels
kubectl get pods -n production --show-labels

# Test selector
kubectl get pods -n production -l app=backend

# Check if selector matches
kubectl describe cnp my-policy -n production
```

### Policy Debugging Commands

```bash
# Check policy enforcement per pod
kubectl exec -n kube-system ds/cilium -- cilium policy get <pod-endpoint-id>

# Trace policy decision
kubectl exec -n kube-system ds/cilium -- cilium policy trace \
  --src-k8s-pod production:frontend \
  --dst-k8s-pod production:backend \
  --dport 8080

# Check identity
kubectl exec -n kube-system ds/cilium -- cilium identity list

# Monitor policy updates
kubectl exec -n kube-system ds/cilium -- cilium monitor --type policy-verdict
```

---

## Best Practices

1. **Start with default-deny**, then allow specific traffic
2. **Use audit mode** before enforcing new policies
3. **Prefer identity-based policies** over CIDR-based
4. **Always allow DNS and kube-apiserver** unless explicitly restricted
5. **Use labels consistently** across pods and policies
6. **Document policy intent** with annotations and comments
7. **Test in staging** before production deployment
8. **Monitor policy verdicts** with Hubble continuously
9. **Review and prune** unused policies regularly
10. **Use specific FQDN patterns**, avoid overly broad wildcards

---

## Quick Reference

### Policy Selectors

| Selector | Description | Example |
|----------|-------------|---------|
| `endpointSelector` | Select pods in same namespace | `matchLabels: {app: web}` |
| `nodeSelector` | Select nodes (cluster-wide policies) | `matchLabels: {role: worker}` |
| `fromEndpoints` | Source pod identity | `matchLabels: {app: frontend}` |
| `toEndpoints` | Destination pod identity | `matchLabels: {app: backend}` |
| `fromCIDR` | Source IP ranges | `- 10.0.0.0/16` |
| `toCIDR` | Destination IP ranges | `- 203.0.113.0/24` |
| `fromEntities` | Source entities | `- kube-apiserver` |
| `toEntities` | Destination entities | `- world` |
| `toFQDNs` | Domain names | `matchName: "api.example.com"` |
| `toServices` | Kubernetes services | `serviceName: backend-svc` |

### Protocol Rules

| Protocol | Rule Field | Example |
|----------|------------|---------|
| HTTP | `http` | `method: "GET", path: "/api/.*"` |
| Kafka | `kafka` | `role: "produce", topic: "events"` |
| DNS | `dns` | `matchPattern: "*.example.com"` |

For Hubble observability and troubleshooting workflows, see `observability.md`.
