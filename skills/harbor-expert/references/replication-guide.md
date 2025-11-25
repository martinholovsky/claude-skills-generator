# Harbor Replication and Disaster Recovery Guide

## Multi-Region Replication Strategies

This reference provides comprehensive patterns for multi-region replication, disaster recovery, and registry federation in Harbor.

---

## 1. Replication Architecture Patterns

### Pattern 1: Hub-and-Spoke (Single Primary)

```
┌─────────────────┐
│  Primary Harbor │ (us-east-1)
│   (Read/Write)  │
└────────┬────────┘
         │ Push replication
         ├──────────────┬──────────────┬──────────────┐
         │              │              │              │
    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐   ┌────▼────┐
    │ Harbor  │    │ Harbor  │    │ Harbor  │   │ Harbor  │
    │ EU-West │    │ AP-SE   │    │ US-West │   │ SA-East │
    │ (RO)    │    │ (RO)    │    │ (RO)    │   │ (RO)    │
    └─────────┘    └─────────┘    └─────────┘   └─────────┘
```

**Use case**: Global content delivery, single source of truth
**Pros**: Simple, consistent, no conflicts
**Cons**: Single point of failure, higher latency for writes

### Pattern 2: Active-Active (Multi-Primary)

```
┌─────────────────┐          ┌─────────────────┐
│  Harbor US-East │◄────────►│  Harbor EU-West │
│   (Read/Write)  │  Bidirectional │   (Read/Write)  │
└────────┬────────┘  Replication   └────────┬────────┘
         │                                   │
         │ Push replication                 │ Push replication
         │                                   │
    ┌────▼────┐                         ┌────▼────┐
    │ Harbor  │                         │ Harbor  │
    │ AP-SE   │                         │ SA-East │
    │ (RO)    │                         │ (RO)    │
    └─────────┘                         └─────────┘
```

**Use case**: Global development teams, regional autonomy
**Pros**: No single point of failure, low latency
**Cons**: Conflict resolution needed, complex

### Pattern 3: Disaster Recovery (Primary-Secondary)

```
┌─────────────────┐
│  Primary Harbor │ (us-east-1)
│   (Read/Write)  │
└────────┬────────┘
         │ Continuous pull replication
         │ + Manual failover
    ┌────▼────┐
    │ Secondary│
    │ Harbor  │ (us-west-2)
    │(Standby)│
    └─────────┘
```

**Use case**: Business continuity, failover
**Pros**: Simple DR, tested backup
**Cons**: Manual failover, RPO/RTO considerations

---

## 2. Replication Configuration

### Create Replication Endpoints

```bash
#!/bin/bash
# configure-endpoints.sh - Set up replication endpoints

HARBOR_URL="https://harbor-primary.example.com"
HARBOR_USER="admin"
HARBOR_PASSWORD="${HARBOR_ADMIN_PASSWORD}"

# Create endpoint for EU region
curl -X POST "${HARBOR_URL}/api/v2.0/registries" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "harbor-eu-west",
    "description": "EU West Harbor registry",
    "url": "https://harbor-eu.example.com",
    "credential": {
      "access_key": "robot$replication-eu",
      "access_secret": "'${EU_ROBOT_TOKEN}'"
    },
    "type": "harbor",
    "insecure": false
  }'

# Create endpoint for AP region
curl -X POST "${HARBOR_URL}/api/v2.0/registries" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "harbor-ap-southeast",
    "description": "Asia Pacific Harbor registry",
    "url": "https://harbor-ap.example.com",
    "credential": {
      "access_key": "robot$replication-ap",
      "access_secret": "'${AP_ROBOT_TOKEN}'"
    },
    "type": "harbor",
    "insecure": false
  }'

# Verify endpoints
curl -X GET "${HARBOR_URL}/api/v2.0/registries" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" | jq
```

### Push-Based Replication Rules

```bash
#!/bin/bash
# create-push-replication.sh - Configure push replication

HARBOR_URL="https://harbor-primary.example.com"

# Production images to EU (immediate push)
curl -X POST "${HARBOR_URL}/api/v2.0/replication/policies" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-to-eu",
    "description": "Replicate production images to EU on push",
    "dest_registry": {
      "id": 1
    },
    "src_registry": null,
    "dest_namespace": "production",
    "dest_namespace_replace_count": 0,
    "trigger": {
      "type": "event_based",
      "trigger_settings": null
    },
    "filters": [
      {
        "type": "name",
        "value": "production/**"
      },
      {
        "type": "tag",
        "value": "v[0-9]*"
      },
      {
        "type": "label",
        "value": "replicate=true"
      }
    ],
    "replicate_deletion": false,
    "deletion": false,
    "override": true,
    "enabled": true,
    "speed": -1
  }'

# All images to AP (scheduled nightly)
curl -X POST "${HARBOR_URL}/api/v2.0/replication/policies" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "all-to-ap-nightly",
    "description": "Nightly sync to Asia Pacific",
    "dest_registry": {
      "id": 2
    },
    "dest_namespace": "",
    "trigger": {
      "type": "scheduled",
      "trigger_settings": {
        "cron": "0 2 * * *"
      }
    },
    "filters": [
      {
        "type": "name",
        "value": "**"
      }
    ],
    "deletion": true,
    "override": true,
    "enabled": true,
    "speed": 0
  }'
```

### Pull-Based Replication Rules

```bash
#!/bin/bash
# create-pull-replication.sh - Configure pull replication

SECONDARY_HARBOR="https://harbor-dr.example.com"

# Pull all production images from primary
curl -X POST "${SECONDARY_HARBOR}/api/v2.0/replication/policies" \
  -u "admin:${DR_HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dr-pull-production",
    "description": "DR: Pull production images from primary",
    "src_registry": {
      "id": 1
    },
    "dest_registry": null,
    "dest_namespace": "production",
    "trigger": {
      "type": "scheduled",
      "trigger_settings": {
        "cron": "*/15 * * * *"
      }
    },
    "filters": [
      {
        "type": "name",
        "value": "production/**"
      },
      {
        "type": "resource",
        "value": "image"
      }
    ],
    "replicate_deletion": true,
    "deletion": false,
    "override": true,
    "enabled": true,
    "speed": -1
  }'
```

---

## 3. Advanced Filtering Strategies

### Label-Based Replication

```bash
# Only replicate images with specific labels

# 1. Add label to image
curl -X POST "https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/v1.0.0/labels" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1
  }'

# 2. Create label filter in replication rule
{
  "filters": [
    {
      "type": "label",
      "value": "production"
    }
  ]
}
```

### Resource Type Filtering

```bash
# Replicate only specific artifact types
{
  "filters": [
    {
      "type": "resource",
      "value": "image"
    }
  ]
}

# Available resource types:
# - image: Docker/OCI images
# - chart: Helm charts
# - cnab: CNAB bundles
# - all: All artifact types
```

### Complex Pattern Matching

```bash
# Replicate semantic versioned images only
{
  "filters": [
    {
      "type": "tag",
      "value": "v[0-9]+\\.[0-9]+\\.[0-9]+"
    }
  ]
}

# Exclude development/testing images
{
  "filters": [
    {
      "type": "tag",
      "value": "{v*,release-*}"
    },
    {
      "type": "tag",
      "value": "!{dev-*,test-*,pr-*}"
    }
  ]
}
```

---

## 4. Disaster Recovery Procedures

### DR Setup and Configuration

```bash
#!/bin/bash
# setup-dr.sh - Configure disaster recovery harbor

PRIMARY="https://harbor-primary.example.com"
DR="https://harbor-dr.example.com"

# 1. Create robot account on primary for DR pulls
PRIMARY_ROBOT=$(curl -X POST "${PRIMARY}/api/v2.0/robots" \
  -u "admin:${PRIMARY_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dr-replication",
    "description": "DR replication robot",
    "duration": -1,
    "level": "system",
    "permissions": [
      {
        "kind": "project",
        "namespace": "*",
        "access": [
          {"resource": "repository", "action": "pull"},
          {"resource": "repository", "action": "list"}
        ]
      }
    ]
  }' | jq -r '.secret')

# 2. Register primary as source on DR
curl -X POST "${DR}/api/v2.0/registries" \
  -u "admin:${DR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "primary-harbor",
    "url": "'${PRIMARY}'",
    "credential": {
      "access_key": "robot$dr-replication",
      "access_secret": "'${PRIMARY_ROBOT}'"
    },
    "type": "harbor"
  }'

# 3. Create comprehensive pull replication
curl -X POST "${DR}/api/v2.0/replication/policies" \
  -u "admin:${DR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dr-full-sync",
    "description": "Full disaster recovery sync",
    "src_registry": {"id": 1},
    "dest_namespace": "",
    "trigger": {
      "type": "scheduled",
      "trigger_settings": {"cron": "*/10 * * * *"}
    },
    "filters": [{"type": "name", "value": "**"}],
    "replicate_deletion": true,
    "override": true,
    "enabled": true
  }'
```

### Failover Procedure

```bash
#!/bin/bash
# failover-to-dr.sh - Failover from primary to DR

DR_HARBOR="https://harbor-dr.example.com"
DNS_ZONE="example.com"

echo "=== Harbor Failover Procedure ==="
echo "This will failover from primary to DR harbor"
read -p "Are you sure? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Failover cancelled"
  exit 0
fi

# 1. Verify DR is healthy
echo "[1/5] Checking DR harbor health..."
DR_HEALTH=$(curl -s "${DR_HARBOR}/api/v2.0/health" | jq -r '.status')
if [ "$DR_HEALTH" != "healthy" ]; then
  echo "ERROR: DR harbor is not healthy (status: ${DR_HEALTH})"
  exit 1
fi

# 2. Trigger final sync from primary
echo "[2/5] Triggering final sync..."
EXEC_ID=$(curl -s -X POST "${DR_HARBOR}/api/v2.0/replication/executions" \
  -u "admin:${DR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"policy_id": 1}' | jq -r '.id')

# Wait for sync to complete
while true; do
  STATUS=$(curl -s "${DR_HARBOR}/api/v2.0/replication/executions/${EXEC_ID}" \
    -u "admin:${DR_PASSWORD}" | jq -r '.status')
  if [ "$STATUS" == "Succeed" ]; then
    break
  elif [ "$STATUS" == "Failed" ]; then
    echo "ERROR: Final sync failed"
    exit 1
  fi
  echo "Waiting for sync... (status: ${STATUS})"
  sleep 5
done

# 3. Disable replication on DR (prevent pulls from failed primary)
echo "[3/5] Disabling replication..."
curl -X PUT "${DR_HARBOR}/api/v2.0/replication/policies/1" \
  -u "admin:${DR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# 4. Update DNS to point to DR
echo "[4/5] Updating DNS..."
# This is provider-specific; example for Route53:
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "harbor.'${DNS_ZONE}'",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "harbor-dr.'${DNS_ZONE}'"}]
      }
    }]
  }'

# 5. Verify failover
echo "[5/5] Verifying failover..."
sleep 10
NEW_TARGET=$(dig +short harbor.${DNS_ZONE} | tail -n1)
echo "DNS now points to: ${NEW_TARGET}"

echo ""
echo "=== Failover Complete ==="
echo "Harbor is now serving from DR location"
echo "RTO achieved: $(date)"
echo ""
echo "Next steps:"
echo "- Notify teams of failover"
echo "- Update monitoring dashboards"
echo "- Investigate primary failure"
echo "- Plan failback when primary is restored"
```

### Failback Procedure

```bash
#!/bin/bash
# failback-to-primary.sh - Restore primary as active

PRIMARY_HARBOR="https://harbor-primary.example.com"
DR_HARBOR="https://harbor-dr.example.com"

echo "=== Harbor Failback Procedure ==="
read -p "Is primary fully restored and healthy? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Failback cancelled. Restore primary first."
  exit 0
fi

# 1. Verify primary is healthy
echo "[1/6] Checking primary harbor health..."
PRIMARY_HEALTH=$(curl -s "${PRIMARY_HARBOR}/api/v2.0/health" | jq -r '.status')
if [ "$PRIMARY_HEALTH" != "healthy" ]; then
  echo "ERROR: Primary harbor is not healthy"
  exit 1
fi

# 2. Sync DR changes back to primary (catch-up)
echo "[2/6] Syncing DR changes to primary..."
# Temporarily create reverse replication
# (This assumes primary was configured with DR as endpoint)
curl -X POST "${PRIMARY_HARBOR}/api/v2.0/replication/executions" \
  -u "admin:${PRIMARY_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"policy_id": 99}' # Reverse sync policy

# 3. Wait for sync
echo "[3/6] Waiting for sync completion..."
sleep 60  # Adjust based on data size

# 4. Update DNS back to primary
echo "[4/6] Updating DNS to primary..."
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "harbor.example.com",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "harbor-primary.example.com"}]
      }
    }]
  }'

# 5. Re-enable forward replication (primary -> DR)
echo "[5/6] Re-enabling DR replication..."
curl -X PUT "${DR_HARBOR}/api/v2.0/replication/policies/1" \
  -u "admin:${DR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# 6. Verify
echo "[6/6] Verifying failback..."
sleep 10
echo "DNS now points to: $(dig +short harbor.example.com | tail -n1)"

echo ""
echo "=== Failback Complete ==="
echo "Primary harbor is now active"
echo "DR replication is re-enabled"
```

---

## 5. Replication Monitoring

### Monitoring Script

```python
#!/usr/bin/env python3
# monitor-replication.py - Monitor replication health

import requests
from requests.auth import HTTPBasicAuth
import time
import os
from datetime import datetime, timedelta

HARBOR_URL = "https://harbor.example.com"
USERNAME = "admin"
PASSWORD = os.environ["HARBOR_PASSWORD"]

auth = HTTPBasicAuth(USERNAME, PASSWORD)

def check_replication_health():
    """Check health of all replication policies"""
    policies_url = f"{HARBOR_URL}/api/v2.0/replication/policies"
    policies = requests.get(policies_url, auth=auth).json()

    alerts = []

    for policy in policies:
        policy_id = policy["id"]
        policy_name = policy["name"]
        enabled = policy["enabled"]

        if not enabled:
            continue

        # Get recent executions
        exec_url = f"{HARBOR_URL}/api/v2.0/replication/executions"
        params = {"policy_id": policy_id, "page_size": 10}
        executions = requests.get(exec_url, auth=auth, params=params).json()

        if not executions:
            alerts.append({
                "severity": "warning",
                "policy": policy_name,
                "message": "No executions found"
            })
            continue

        latest = executions[0]
        status = latest["status"]
        end_time = latest.get("end_time")

        # Check for failures
        if status == "Failed":
            alerts.append({
                "severity": "critical",
                "policy": policy_name,
                "message": f"Replication failed: {latest.get('status_text')}"
            })

        # Check for staleness (>24h since last success)
        if end_time:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            age = datetime.now(end_dt.tzinfo) - end_dt
            if age > timedelta(hours=24) and status == "Succeed":
                alerts.append({
                    "severity": "warning",
                    "policy": policy_name,
                    "message": f"Last successful replication {age.total_seconds() / 3600:.1f}h ago"
                })

        # Check replication lag
        if status == "InProgress":
            start_time = latest.get("start_time")
            if start_time:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                duration = datetime.now(start_dt.tzinfo) - start_dt
                if duration > timedelta(hours=1):
                    alerts.append({
                        "severity": "warning",
                        "policy": policy_name,
                        "message": f"Replication in progress for {duration.total_seconds() / 60:.0f} minutes"
                    })

    return alerts

def send_alerts(alerts):
    """Send alerts to monitoring system"""
    if not alerts:
        print(f"[{datetime.now()}] All replication policies healthy")
        return

    for alert in alerts:
        severity = alert["severity"]
        policy = alert["policy"]
        message = alert["message"]
        print(f"[{datetime.now()}] [{severity.upper()}] {policy}: {message}")

        # Send to alerting system (PagerDuty, Slack, etc.)
        # Example: send_to_pagerduty(alert)

if __name__ == "__main__":
    while True:
        try:
            alerts = check_replication_health()
            send_alerts(alerts)
        except Exception as e:
            print(f"[{datetime.now()}] [ERROR] Monitoring failed: {e}")

        time.sleep(300)  # Check every 5 minutes
```

### Prometheus Metrics Exporter

```python
#!/usr/bin/env python3
# harbor-replication-exporter.py - Export replication metrics to Prometheus

from prometheus_client import start_http_server, Gauge, Counter
import requests
from requests.auth import HTTPBasicAuth
import time
import os

HARBOR_URL = "https://harbor.example.com"
USERNAME = "admin"
PASSWORD = os.environ["HARBOR_PASSWORD"]

auth = HTTPBasicAuth(USERNAME, PASSWORD)

# Metrics
replication_status = Gauge('harbor_replication_status',
                           'Replication status (1=success, 0=failed, -1=in_progress)',
                           ['policy', 'destination'])
replication_lag_seconds = Gauge('harbor_replication_lag_seconds',
                                'Time since last successful replication',
                                ['policy', 'destination'])
replication_total = Counter('harbor_replication_total',
                            'Total replication executions',
                            ['policy', 'destination', 'status'])

def collect_metrics():
    """Collect replication metrics"""
    policies_url = f"{HARBOR_URL}/api/v2.0/replication/policies"
    policies = requests.get(policies_url, auth=auth).json()

    for policy in policies:
        policy_id = policy["id"]
        policy_name = policy["name"]

        # Get destination registry name
        dest_registry = policy.get("dest_registry", {})
        dest_name = dest_registry.get("name", "local") if dest_registry else "local"

        # Get latest execution
        exec_url = f"{HARBOR_URL}/api/v2.0/replication/executions"
        params = {"policy_id": policy_id, "page_size": 1}
        executions = requests.get(exec_url, auth=auth, params=params).json()

        if executions:
            latest = executions[0]
            status = latest["status"]

            # Status metric
            if status == "Succeed":
                replication_status.labels(policy=policy_name, destination=dest_name).set(1)
            elif status == "Failed":
                replication_status.labels(policy=policy_name, destination=dest_name).set(0)
            else:
                replication_status.labels(policy=policy_name, destination=dest_name).set(-1)

            # Lag metric
            end_time = latest.get("end_time")
            if end_time and status == "Succeed":
                from datetime import datetime
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                lag = (datetime.now(end_dt.tzinfo) - end_dt).total_seconds()
                replication_lag_seconds.labels(policy=policy_name, destination=dest_name).set(lag)

if __name__ == "__main__":
    start_http_server(9100)
    print("Harbor replication exporter running on :9100")

    while True:
        try:
            collect_metrics()
        except Exception as e:
            print(f"Error collecting metrics: {e}")
        time.sleep(60)
```

---

## 6. Bandwidth Optimization

### Scheduled Replication for Large Datasets

```bash
# Replicate during off-peak hours
{
  "trigger": {
    "type": "scheduled",
    "trigger_settings": {
      "cron": "0 2 * * *"  # 2 AM daily
    }
  },
  "speed": 10485760  # Limit to 10 MB/s
}
```

### Incremental Replication

```bash
# Only replicate changed artifacts
{
  "filters": [
    {
      "type": "name",
      "value": "**"
    }
  ],
  "override": false  # Don't re-replicate existing artifacts
}
```

### Compression and Deduplication

Harbor automatically uses registry blob deduplication. Images sharing layers only transfer unique blobs.

---

## 7. Conflict Resolution

### Handling Tag Conflicts

```bash
# Strategy 1: Override (last write wins)
{
  "override": true
}

# Strategy 2: Preserve destination
{
  "override": false
}
```

### Bidirectional Replication Conflicts

For active-active setups, implement tag naming conventions:

```bash
# Region-specific tag prefixes
# us-east: myapp:v1.0.0-use1
# eu-west: myapp:v1.0.0-euw1

# Replicate with filters
{
  "filters": [
    {
      "type": "tag",
      "value": "!*-use1"  # Don't replicate US tags back to US
    }
  ]
}
```

---

## Summary

This guide provides production-ready patterns for:
- **Architecture Patterns**: Hub-and-spoke, active-active, disaster recovery
- **Replication Configuration**: Push/pull rules, advanced filtering
- **Disaster Recovery**: Complete failover/failback procedures
- **Monitoring**: Health checks, Prometheus metrics, alerting
- **Optimization**: Bandwidth management, incremental sync
- **Conflict Resolution**: Tag management, bidirectional strategies

Use these patterns to implement highly available, globally distributed Harbor registries with tested disaster recovery procedures.

---

## RTO/RPO Targets

| Scenario | RTO (Recovery Time) | RPO (Data Loss) | Configuration |
|----------|---------------------|-----------------|---------------|
| **DR Failover** | < 15 minutes | < 15 minutes | Pull replication every 10min |
| **Regional Cache** | N/A | N/A | Event-based push replication |
| **Compliance Archive** | < 4 hours | < 24 hours | Daily scheduled pull |
| **Development Sync** | < 1 hour | < 1 hour | Hourly scheduled push |

Adjust replication frequency based on your specific RTO/RPO requirements.
