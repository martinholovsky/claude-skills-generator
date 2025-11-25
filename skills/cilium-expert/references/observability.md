# Cilium Observability with Hubble - Comprehensive Guide

This document provides detailed setup, configuration, and usage patterns for Hubble - Cilium's observability platform for network flows, service maps, and security monitoring.

## Table of Contents

1. [Hubble Installation & Setup](#hubble-installation--setup)
2. [Flow Monitoring](#flow-monitoring)
3. [Service Maps & Topology](#service-maps--topology)
4. [Metrics & Prometheus Integration](#metrics--prometheus-integration)
5. [Troubleshooting Workflows](#troubleshooting-workflows)
6. [Security Monitoring](#security-monitoring)
7. [Performance Tuning](#performance-tuning)

---

## Hubble Installation & Setup

### Basic Installation

**Install Hubble with Cilium:**

```bash
# Via Helm
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

# Verify installation
kubectl get pods -n kube-system -l k8s-app=hubble-relay
kubectl get pods -n kube-system -l k8s-app=hubble-ui
```

**Install Hubble CLI:**

```bash
# Download latest Hubble CLI
export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-amd64.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-amd64.tar.gz /usr/local/bin
rm hubble-linux-amd64.tar.gz{,.sha256sum}

# Verify
hubble version
```

### Advanced Configuration

**Enable L7 visibility:**

```yaml
# Via Helm values
hubble:
  enabled: true
  relay:
    enabled: true
  ui:
    enabled: true
  # L7 protocols
  l7:
    enabled: true
  # Flow export
  export:
    fileMaxSizeMb: 10
    fileMaxBackups: 5
  # Metrics
  metrics:
    enabled:
    - dns:query;ignoreAAAA
    - drop
    - tcp
    - flow:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|reserved-identity
    - port-distribution
    - icmp
    - http
```

**Configure flow retention:**

```yaml
# Hubble relay configuration
hubble:
  relay:
    enabled: true
    replicas: 2  # HA
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 1000m
        memory: 1Gi
    # Flow buffer size
    ringBufferSize: 65535
```

**Port forwarding for access:**

```bash
# Hubble Relay (for CLI)
kubectl port-forward -n kube-system svc/hubble-relay 4245:80 &

# Hubble UI
kubectl port-forward -n kube-system svc/hubble-ui 12000:80 &

# Or use cilium CLI
cilium hubble ui
```

---

## Flow Monitoring

### Basic Flow Observation

**Watch all flows:**

```bash
# Real-time flow monitoring
hubble observe

# Follow flows (like tail -f)
hubble observe --follow

# Limit output
hubble observe --last 100
```

**Filter by namespace:**

```bash
# Specific namespace
hubble observe --namespace production

# Multiple namespaces
hubble observe --namespace production,staging

# All namespaces except system
hubble observe --not-namespace kube-system
```

**Filter by pod:**

```bash
# Specific pod
hubble observe --pod production/frontend-7d4c8b6f9-x2m5k

# Pod name pattern
hubble observe --pod production/frontend

# Multiple pods
hubble observe --pod production/frontend,production/backend
```

### Flow Filtering

**By verdict (policy decision):**

```bash
# Forwarded (allowed) traffic
hubble observe --verdict FORWARDED

# Dropped traffic (policy deny, errors)
hubble observe --verdict DROPPED

# Denied by policy
hubble observe --verdict DENIED

# Audit mode (would be denied)
hubble observe --verdict AUDIT

# Redirected traffic
hubble observe --verdict REDIRECTED

# Encrypted traffic
hubble observe --verdict ENCRYPTED

# All verdicts
hubble observe --verdict all
```

**By protocol:**

```bash
# TCP traffic
hubble observe --protocol tcp

# UDP traffic
hubble observe --protocol udp

# HTTP traffic (requires L7 policy)
hubble observe --protocol http

# DNS traffic
hubble observe --protocol dns

# ICMP (ping)
hubble observe --protocol icmp
```

**By port:**

```bash
# Specific port
hubble observe --port 8080

# HTTPS traffic
hubble observe --port 443

# DNS traffic
hubble observe --port 53
```

**By direction:**

```bash
# Ingress traffic
hubble observe --type trace:to-endpoint

# Egress traffic
hubble observe --type trace:from-endpoint

# Both directions
hubble observe --type trace
```

### Advanced Filtering

**Combining filters:**

```bash
# Dropped HTTP traffic to production namespace
hubble observe \
  --namespace production \
  --protocol http \
  --verdict DROPPED

# DNS queries from specific pod
hubble observe \
  --from-pod production/frontend-7d4c8b6f9-x2m5k \
  --protocol dns \
  --port 53

# All denied traffic to backend service
hubble observe \
  --to-service production/backend \
  --verdict DENIED
```

**By labels:**

```bash
# Traffic from pods with label app=frontend
hubble observe --from-label app=frontend

# Traffic to pods with label tier=database
hubble observe --to-label tier=database

# Combine multiple labels
hubble observe \
  --from-label app=frontend \
  --to-label tier=backend,env=production
```

**By IP address:**

```bash
# From specific IP
hubble observe --from-ip 10.0.1.42

# To specific CIDR
hubble observe --to-ip 10.0.0.0/16

# From and to
hubble observe \
  --from-ip 10.0.1.42 \
  --to-ip 10.0.2.0/24
```

**By identity:**

```bash
# From specific Cilium identity
hubble observe --from-identity 12345

# To reserved identity (host, world, etc.)
hubble observe --to-identity reserved:host
hubble observe --to-identity reserved:world
```

### Output Formats

**JSON output:**

```bash
# JSON format
hubble observe --output json

# Compact JSON
hubble observe --output compact

# Pretty-printed JSON
hubble observe --output json | jq '.'

# Extract specific fields
hubble observe --output json | jq -r '.flow | "\(.time) \(.source.namespace)/\(.source.pod_name) -> \(.destination.namespace)/\(.destination.pod_name)"'
```

**Dictionary output (tab-separated):**

```bash
hubble observe --output dict
```

**Jsonpb (protocol buffers JSON):**

```bash
hubble observe --output jsonpb
```

---

## Service Maps & Topology

### Hubble UI

**Access Hubble UI:**

```bash
# Port forward
cilium hubble ui

# Or manually
kubectl port-forward -n kube-system svc/hubble-ui 12000:80
# Open http://localhost:12000
```

**Hubble UI features:**
- Real-time service map visualization
- Interactive topology graphs
- Flow filtering by namespace, service, verdict
- L7 protocol details (HTTP methods, paths, status codes)
- Time-range selection for historical analysis

### Service Dependency Mapping

**Generate service map with CLI:**

```bash
# Show all service-to-service flows
hubble observe --output compact | \
  awk '{print $4 " -> " $6}' | \
  sort | uniq -c | sort -nr

# Service dependencies in namespace
hubble observe --namespace production \
  --output json | \
  jq -r '
    select(.flow.l7.http != null) |
    "\(.flow.source.namespace)/\(.flow.source.pod_name) -> \(.flow.destination.namespace)/\(.flow.destination.pod_name): \(.flow.l7.http.method) \(.flow.l7.http.url)"
  ' | sort | uniq
```

**Identify external dependencies:**

```bash
# Traffic to outside cluster (world)
hubble observe --to-identity reserved:world \
  --output json | \
  jq -r '.flow | "\(.source.namespace)/\(.source.pod_name) -> \(.destination.fqdns[])"' | \
  sort | uniq
```

---

## Metrics & Prometheus Integration

### Hubble Metrics

**Enable Hubble metrics:**

```bash
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"
```

**Available metric types:**
- `dns`: DNS queries and responses
- `drop`: Dropped packets and reasons
- `tcp`: TCP connections and flags
- `flow`: Network flows with context
- `port-distribution`: Traffic distribution by port
- `icmp`: ICMP messages
- `http`: HTTP requests (requires L7 policy)

**Metric configuration examples:**

```yaml
# DNS metrics with query details
hubble.metrics.enabled:
- dns:query;ignoreAAAA  # Ignore AAAA queries
- dns:query;labelsContext=source_namespace,destination_namespace

# Flow metrics with workload context
hubble.metrics.enabled:
- flow:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|reserved-identity

# HTTP metrics with detailed labels
hubble.metrics.enabled:
- http:exemplars=true;labelsContext=source_namespace,destination_namespace,destination_workload
```

### Prometheus Integration

**ServiceMonitor for Prometheus Operator:**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: hubble-metrics
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: hubble
  endpoints:
  - port: hubble-metrics
    interval: 30s
    path: /metrics
```

**Manual Prometheus scrape config:**

```yaml
scrape_configs:
- job_name: 'hubble-metrics'
  kubernetes_sd_configs:
  - role: pod
    namespaces:
      names:
      - kube-system
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_label_k8s_app]
    action: keep
    regex: hubble
  - source_labels: [__meta_kubernetes_pod_container_port_name]
    action: keep
    regex: hubble-metrics
```

### Key Metrics

**Flow metrics:**

```promql
# Total flows by verdict
sum by (verdict) (rate(hubble_flows_processed_total[5m]))

# Dropped flows by reason
sum by (drop_reason) (rate(hubble_drop_total[5m]))

# Flow rate by namespace
sum by (source_namespace, destination_namespace) (rate(hubble_flows_processed_total{verdict="FORWARDED"}[5m]))
```

**DNS metrics:**

```promql
# DNS query rate
rate(hubble_dns_queries_total[5m])

# DNS query latency
histogram_quantile(0.95, rate(hubble_dns_query_duration_seconds_bucket[5m]))

# DNS errors
rate(hubble_dns_responses_total{rcode!="NOERROR"}[5m])
```

**HTTP metrics:**

```promql
# HTTP request rate
rate(hubble_http_requests_total[5m])

# HTTP errors (5xx)
rate(hubble_http_requests_total{status=~"5.."}[5m])

# HTTP latency (p95)
histogram_quantile(0.95, rate(hubble_http_request_duration_seconds_bucket[5m]))
```

**Drop metrics:**

```promql
# Drop rate by reason
sum by (drop_reason) (rate(hubble_drop_total[5m]))

# Policy deny rate
rate(hubble_drop_total{drop_reason="Policy denied"}[5m])

# Invalid packet drops
rate(hubble_drop_total{drop_reason=~"Invalid.*"}[5m])
```

### Grafana Dashboards

**Import official Cilium dashboards:**

1. Cilium Agent Dashboard (ID: 16611)
2. Cilium Operator Dashboard (ID: 16612)
3. Hubble Dashboard (ID: 16613)

```bash
# Or via URL
https://grafana.com/grafana/dashboards/16611
https://grafana.com/grafana/dashboards/16612
https://grafana.com/grafana/dashboards/16613
```

---

## Troubleshooting Workflows

### Connectivity Issues

**Debug connection failures:**

```bash
# 1. Check if traffic is being dropped
hubble observe \
  --from-pod production/frontend-7d4c8b6f9-x2m5k \
  --to-pod production/backend-5f8d9c4b2-p7k3n \
  --verdict DROPPED

# 2. Check policy verdict
hubble observe \
  --from-pod production/frontend-7d4c8b6f9-x2m5k \
  --to-pod production/backend-5f8d9c4b2-p7k3n \
  --verdict DENIED

# 3. Check if DNS resolution is working
hubble observe \
  --from-pod production/frontend-7d4c8b6f9-x2m5k \
  --protocol dns

# 4. Check if traffic reaches destination
hubble observe \
  --from-pod production/frontend-7d4c8b6f9-x2m5k \
  --to-pod production/backend-5f8d9c4b2-p7k3n \
  --verdict FORWARDED
```

### Policy Troubleshooting

**Identify policy denies:**

```bash
# All denied traffic in namespace
hubble observe --namespace production --verdict DENIED

# Denied traffic to specific service
hubble observe --to-service production/backend --verdict DENIED

# See which pods are being blocked
hubble observe --verdict DENIED --output json | \
  jq -r '.flow | "\(.source.namespace)/\(.source.pod_name) -X-> \(.destination.namespace)/\(.destination.pod_name) (Policy: \(.policy_match_type))"' | \
  sort | uniq -c | sort -nr
```

**Test policy changes:**

```bash
# Enable audit mode on policy
kubectl annotate cnp my-policy -n production cilium.io/policy-audit-mode="true"

# Watch audit verdicts
hubble observe --verdict AUDIT --namespace production

# See what would be denied
hubble observe --verdict AUDIT --type drop
```

### DNS Troubleshooting

**Debug DNS issues:**

```bash
# Check DNS queries
hubble observe --protocol dns --namespace production

# Failed DNS queries
hubble observe --protocol dns --output json | \
  jq -r 'select(.flow.l7.dns.rcode != "NOERROR") | .flow'

# DNS query latency
hubble observe --protocol dns --output json | \
  jq -r '.flow.l7.dns | "\(.query) - \(.qtypes[]) - \(.rcode)"'

# DNS queries to specific domain
hubble observe --protocol dns --output json | \
  jq -r 'select(.flow.l7.dns.query | contains("example.com")) | .flow'
```

### Performance Debugging

**High latency investigation:**

```bash
# HTTP request latency (requires L7 policy)
hubble observe --protocol http --output json | \
  jq -r '.flow.l7.http | "\(.method) \(.url) - Status: \(.code)"'

# TCP connection issues
hubble observe --protocol tcp --verdict DROPPED

# Retransmissions
hubble observe --protocol tcp --output json | \
  jq -r 'select(.flow.l4.tcp.flags.SYN and .flow.l4.tcp.flags.ACK) | .flow'
```

### Security Incident Investigation

**Investigate suspicious activity:**

```bash
# Egress to unexpected external IPs
hubble observe --to-identity reserved:world \
  --output json | \
  jq -r '.flow | "\(.time) \(.source.namespace)/\(.source.pod_name) -> \(.destination.ip)"' | \
  sort | uniq

# Unauthorized access attempts
hubble observe --verdict DENIED \
  --output json | \
  jq -r '.flow | "\(.time) \(.source.namespace)/\(.source.pod_name) -X-> \(.destination.namespace)/\(.destination.pod_name):\(.destination.l4.tcp.destination_port)"'

# Unusual DNS queries
hubble observe --protocol dns --output json | \
  jq -r 'select(.flow.l7.dns.query | test("(\\d{1,3}\\.){3}\\d{1,3}")) | .flow'  # Queries for IPs
```

---

## Security Monitoring

### Anomaly Detection

**Monitor for suspicious patterns:**

```bash
# 1. Excessive DNS queries (potential data exfiltration)
hubble observe --protocol dns --from-pod production/suspicious-pod | \
  wc -l  # High count = suspicious

# 2. Connections to unusual ports
hubble observe --namespace production --output json | \
  jq -r '.flow | select(.destination.l4.tcp.destination_port > 10000) | "\(.source.pod_name) -> port \(.destination.l4.tcp.destination_port)"' | \
  sort | uniq -c

# 3. Lateral movement (cross-namespace access)
hubble observe --from-namespace production --not-to-namespace production | \
  grep -v "kube-system"

# 4. External connections
hubble observe --to-identity reserved:world --namespace production
```

### Compliance Monitoring

**Audit logging for compliance:**

```bash
# All traffic to PCI-scope namespace
hubble observe --to-namespace pci-scope --output json > pci-traffic-audit.json

# Track who accessed sensitive data
hubble observe --to-service production/customer-db --output json | \
  jq -r '.flow | "\(.time) \(.source.namespace)/\(.source.pod_name) accessed database"'

# Failed access attempts (audit trail)
hubble observe --verdict DENIED --output json | \
  jq -r '.flow | "\(.time) DENIED: \(.source.namespace)/\(.source.pod_name) -> \(.destination.namespace)/\(.destination.pod_name)"'
```

### Real-Time Alerting

**Export flows for SIEM integration:**

```bash
# Export to JSON for log aggregation
hubble observe --output json | \
  while read line; do
    echo "$line" | curl -X POST -H "Content-Type: application/json" -d @- http://siem-endpoint/logs
  done
```

**Alert on specific patterns:**

```bash
# Alert on policy denies to sensitive services
hubble observe --to-label sensitivity=high --verdict DENIED --output json | \
  while read line; do
    echo "ALERT: Unauthorized access attempt"
    echo "$line" | jq '.'
  done
```

---

## Performance Tuning

### Optimize Flow Buffer

**Tune ring buffer size:**

```yaml
# Increase buffer for high-traffic clusters
hubble:
  relay:
    ringBufferSize: 131072  # Default: 65535
```

### Reduce Metric Cardinality

**Optimize metric labels:**

```yaml
# Limit context labels to reduce cardinality
hubble:
  metrics:
    enabled:
    - flow:sourceContext=namespace;destinationContext=namespace
    # vs high cardinality:
    # - flow:sourceContext=workload-name;destinationContext=workload-name
```

### Sample High-Volume Flows

**Configure flow sampling:**

```yaml
# Sample 1 in 100 flows for high-volume namespaces
hubble:
  export:
    flowSampling: 100  # Sample rate
```

---

## Advanced Use Cases

### Cross-Cluster Observability

**Monitor ClusterMesh flows:**

```bash
# Flows between clusters
hubble observe --output json | \
  jq -r 'select(.flow.source.cluster_name != .flow.destination.cluster_name) | .flow'

# Cross-cluster service dependencies
hubble observe --output json | \
  jq -r 'select(.flow.destination.cluster_name != null) | "\(.flow.source.cluster_name) -> \(.flow.destination.cluster_name)"' | \
  sort | uniq
```

### Flow Export for Analysis

**Export flows to file:**

```bash
# Export 1 hour of flows
hubble observe --since 1h --output json > flows-1h.json

# Export specific namespace
hubble observe --namespace production --since 24h --output json > production-flows.json

# Analyze with jq
cat flows-1h.json | jq -r '.flow | "\(.source.namespace)/\(.source.pod_name) -> \(.destination.namespace)/\(.destination.pod_name)"' | \
  sort | uniq -c | sort -nr | head -20
```

### Custom Dashboards

**Create custom metrics from flows:**

```bash
# Count flows by verdict
hubble observe --output json | \
  jq -r '.flow.verdict' | \
  sort | uniq -c

# HTTP status code distribution
hubble observe --protocol http --output json | \
  jq -r '.flow.l7.http.code' | \
  sort | uniq -c | sort -nr

# Top talkers (by flow count)
hubble observe --output json | \
  jq -r '"\(.flow.source.namespace)/\(.flow.source.pod_name)"' | \
  sort | uniq -c | sort -nr | head -10
```

---

## Quick Reference

### Common Hubble Commands

```bash
# Real-time flows
hubble observe --follow

# Dropped traffic
hubble observe --verdict DROPPED

# Policy denies
hubble observe --verdict DENIED

# DNS queries
hubble observe --protocol dns

# HTTP traffic
hubble observe --protocol http

# Specific pod
hubble observe --pod namespace/pod-name

# Between two pods
hubble observe --from-pod ns1/pod1 --to-pod ns2/pod2

# Export to JSON
hubble observe --output json > flows.json

# Last 100 flows
hubble observe --last 100

# Since timestamp
hubble observe --since 2024-01-01T10:00:00Z

# UI access
cilium hubble ui
```

### Verdict Types

| Verdict | Meaning |
|---------|---------|
| `FORWARDED` | Traffic allowed and forwarded |
| `DROPPED` | Traffic dropped (policy, error, etc.) |
| `DENIED` | Explicitly denied by policy |
| `AUDIT` | Would be denied (audit mode) |
| `REDIRECTED` | Redirected (proxy, service mesh) |
| `ENCRYPTED` | Encrypted traffic |
| `ERROR` | Processing error |

### Reserved Identities

| Identity | Meaning |
|----------|---------|
| `reserved:host` | Host networking |
| `reserved:world` | External (internet) |
| `reserved:cluster` | Cluster-local |
| `reserved:health` | Cilium health checks |
| `reserved:init` | Pod initialization |
| `reserved:remote-node` | Remote cluster node |
| `reserved:kube-apiserver` | Kubernetes API server |

For comprehensive network policy examples, see `network-policies.md`.
