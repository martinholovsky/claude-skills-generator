# Harbor Security Scanning Reference

## Trivy Integration and CVE Management

This reference provides comprehensive patterns for vulnerability scanning, CVE policy enforcement, and webhook automation in Harbor.

---

## 1. Trivy Scanner Configuration

### Installing and Configuring Trivy Adapter

```yaml
# docker-compose.yml - Trivy service
services:
  trivy:
    image: goharbor/trivy-adapter-photon:v2.10.0
    container_name: trivy-adapter
    restart: always
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
    dns_search: .
    environment:
      SCANNER_LOG_LEVEL: info
      SCANNER_TRIVY_CACHE_DIR: /home/scanner/.cache/trivy
      SCANNER_TRIVY_REPORTS_DIR: /home/scanner/.cache/reports
      SCANNER_TRIVY_DEBUG_MODE: "false"
      SCANNER_TRIVY_VULN_TYPE: "os,library"
      SCANNER_TRIVY_SECURITY_CHECKS: "vuln,config,secret"
      SCANNER_TRIVY_SEVERITY: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
      SCANNER_TRIVY_IGNORE_UNFIXED: "false"
      SCANNER_TRIVY_SKIP_UPDATE: "false"
      SCANNER_TRIVY_OFFLINE_SCAN: "false"
      SCANNER_TRIVY_INSECURE: "false"
      SCANNER_TRIVY_TIMEOUT: "10m"
      SCANNER_API_SERVER_ADDR: ":8080"
      SCANNER_STORE_REDIS_URL: redis://redis:6379
      SCANNER_STORE_REDIS_NAMESPACE: harbor.scanner.trivy:store
      SCANNER_JOB_QUEUE_REDIS_URL: redis://redis:6379
      SCANNER_JOB_QUEUE_REDIS_NAMESPACE: harbor.scanner.trivy:job-queue
    volumes:
      - trivy_cache:/home/scanner/.cache
    networks:
      - harbor
    depends_on:
      - redis

volumes:
  trivy_cache:
```

### Register Trivy Scanner via API

```bash
#!/bin/bash
# register-trivy.sh - Register and configure Trivy scanner

HARBOR_URL="https://harbor.example.com"
HARBOR_USER="admin"
HARBOR_PASSWORD="${HARBOR_ADMIN_PASSWORD}"

# Register scanner
SCANNER_ID=$(curl -X POST "${HARBOR_URL}/api/v2.0/scanners" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Trivy",
    "description": "Aqua Security Trivy vulnerability scanner",
    "url": "http://trivy:8080",
    "vendor": "Aqua Security",
    "version": "0.48.0",
    "auth": "",
    "access_credential": "",
    "skip_cert_verify": false,
    "use_internal_addr": true
  }' | jq -r '.id')

echo "Trivy scanner registered with ID: ${SCANNER_ID}"

# Set as default scanner
curl -X PATCH "${HARBOR_URL}/api/v2.0/scanners/${SCANNER_ID}" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{"is_default": true}'

echo "Trivy set as default scanner"

# Verify configuration
curl -X GET "${HARBOR_URL}/api/v2.0/scanners" \
  -u "${HARBOR_USER}:${HARBOR_PASSWORD}" | jq
```

---

## 2. CVE Policy Configuration

### Project-Level Vulnerability Policies

```bash
#!/bin/bash
# configure-cve-policy.sh - Set up CVE policies for projects

HARBOR_URL="https://harbor.example.com"
PROJECT_NAME="production"

# Get project ID
PROJECT_ID=$(curl -s "${HARBOR_URL}/api/v2.0/projects?name=${PROJECT_NAME}" \
  -u "admin:${HARBOR_PASSWORD}" | jq -r '.[0].project_id')

# Configure strict CVE policy for production
curl -X PUT "${HARBOR_URL}/api/v2.0/projects/${PROJECT_ID}" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "auto_scan": "true",
      "severity": "critical",
      "reuse_sys_cve_allowlist": "false",
      "prevent_vul": "true",
      "enable_content_trust": "true",
      "public": "false"
    }
  }'

echo "CVE policy configured for ${PROJECT_NAME}"
```

### CVE Allowlist Management

```bash
#!/bin/bash
# manage-cve-allowlist.sh - Manage CVE exemptions

HARBOR_URL="https://harbor.example.com"
PROJECT_NAME="library"

# Add time-bound CVE exemption
EXPIRES_AT=$(date -d "+30 days" +%s)

curl -X PUT "${HARBOR_URL}/api/v2.0/projects/${PROJECT_NAME}" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_allowlist": {
      "items": [
        {
          "cve_id": "CVE-2023-45288"
        },
        {
          "cve_id": "CVE-2024-12345"
        }
      ],
      "expires_at": '${EXPIRES_AT}'
    }
  }'

# List current allowlist
curl -X GET "${HARBOR_URL}/api/v2.0/projects/${PROJECT_NAME}" \
  -u "admin:${HARBOR_PASSWORD}" | jq '.cve_allowlist'
```

### Multi-Tier Severity Policies

```yaml
# Project: production
metadata:
  auto_scan: "true"
  severity: "critical"        # Block CRITICAL only
  prevent_vul: "true"          # Enforce blocking
  enable_content_trust: "true" # Require signatures

# Project: staging
metadata:
  auto_scan: "true"
  severity: "high"             # Block HIGH and CRITICAL
  prevent_vul: "true"
  enable_content_trust: "false"

# Project: development
metadata:
  auto_scan: "true"
  severity: "none"             # Scan but don't block
  prevent_vul: "false"
  enable_content_trust: "false"
```

---

## 3. Automated Scanning Workflows

### Scan on Push Configuration

```bash
# Enable scan-on-push globally
curl -X PUT "https://harbor.example.com/api/v2.0/configurations" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_all_policy": {
      "type": "daily",
      "parameter": {
        "daily_time": 0
      }
    }
  }'
```

### Scheduled Rescanning

```bash
#!/bin/bash
# schedule-scans.sh - Configure periodic rescans

HARBOR_URL="https://harbor.example.com"

# Configure daily rescan at 2 AM UTC
curl -X POST "${HARBOR_URL}/api/v2.0/system/scanAll/schedule" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "schedule": {
      "type": "Daily",
      "cron": "0 2 * * *"
    }
  }'

# Trigger manual scan for specific repository
PROJECT="library"
REPO="app"
TAG="v1.0.0"

curl -X POST "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories/${REPO}/artifacts/${TAG}/scan" \
  -u "admin:${HARBOR_PASSWORD}"

# Check scan status
curl -X GET "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories/${REPO}/artifacts/${TAG}" \
  -u "admin:${HARBOR_PASSWORD}" | jq '.scan_overview'
```

### Bulk Scanning Script

```python
#!/usr/bin/env python3
# bulk-scan.py - Scan all artifacts in a project

import requests
from requests.auth import HTTPBasicAuth
import os
import time

HARBOR_URL = "https://harbor.example.com"
USERNAME = "admin"
PASSWORD = os.environ["HARBOR_PASSWORD"]
PROJECT = "library"

auth = HTTPBasicAuth(USERNAME, PASSWORD)
headers = {"Content-Type": "application/json"}

# Get all repositories in project
repos_url = f"{HARBOR_URL}/api/v2.0/projects/{PROJECT}/repositories"
repos = requests.get(repos_url, auth=auth).json()

scanned = 0
failed = 0

for repo in repos:
    repo_name = repo["name"].split("/", 1)[1]

    # Get all artifacts
    artifacts_url = f"{HARBOR_URL}/api/v2.0/projects/{PROJECT}/repositories/{repo_name}/artifacts"
    artifacts = requests.get(artifacts_url, auth=auth).json()

    for artifact in artifacts:
        digest = artifact["digest"]

        # Trigger scan
        scan_url = f"{artifacts_url}/{digest}/scan"
        response = requests.post(scan_url, auth=auth, headers=headers)

        if response.status_code == 202:
            print(f"Scanning {PROJECT}/{repo_name}@{digest[:12]}")
            scanned += 1
        else:
            print(f"Failed to scan {PROJECT}/{repo_name}@{digest[:12]}")
            failed += 1

        time.sleep(0.5)  # Rate limiting

print(f"\nTotal scanned: {scanned}, Failed: {failed}")
```

---

## 4. Webhook Automation

### Webhook Configuration for Scan Events

```bash
#!/bin/bash
# configure-webhooks.sh - Set up webhooks for security events

HARBOR_URL="https://harbor.example.com"
PROJECT="library"
SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"

# Create webhook for scan completion
curl -X POST "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/webhook/policies" \
  -u "admin:${HARBOR_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "security-scan-alerts",
    "description": "Alert on vulnerability scan completion",
    "enabled": true,
    "event_types": [
      "SCANNING_COMPLETED",
      "SCANNING_FAILED",
      "SCANNING_STOPPED"
    ],
    "targets": [
      {
        "type": "http",
        "address": "'${SLACK_WEBHOOK}'",
        "skip_cert_verify": false,
        "payload_format": "CloudEvents",
        "auth_header": ""
      }
    ]
  }'
```

### Webhook Payload Processing

```python
#!/usr/bin/env python3
# webhook-processor.py - Process Harbor webhook events

from flask import Flask, request, jsonify
import json
import requests

app = Flask(__name__)

SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
CVE_THRESHOLD = {
    "Critical": 0,  # Zero tolerance for critical
    "High": 5,      # Alert if >5 high CVEs
    "Medium": 20    # Alert if >20 medium CVEs
}

@app.route("/webhook/harbor/scan", methods=["POST"])
def handle_scan_webhook():
    event = request.json

    if event.get("type") == "harbor.scanning.completed":
        data = event.get("data", {})
        repo = data.get("repository")
        tag = data.get("tag", "")
        scan_overview = data.get("scan_overview", {})
        summary = scan_overview.get("summary", {})

        # Check thresholds
        alerts = []
        for severity, count in summary.items():
            threshold = CVE_THRESHOLD.get(severity, float('inf'))
            if count > threshold:
                alerts.append(f"{severity}: {count} (threshold: {threshold})")

        if alerts:
            message = {
                "text": f":warning: Vulnerability threshold exceeded: {repo}:{tag}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Vulnerability Scan Alert*\n\n"
                                    f"*Image:* `{repo}:{tag}`\n"
                                    f"*Total CVEs:* {scan_overview.get('total_count', 0)}\n"
                                    f"*Fixable:* {scan_overview.get('fixable_count', 0)}\n\n"
                                    f"*Threshold Violations:*\n" + "\n".join([f"• {a}" for a in alerts])
                        }
                    }
                ]
            }
            requests.post(SLACK_WEBHOOK, json=message)

        return jsonify({"status": "processed"}), 200

    return jsonify({"status": "ignored"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

### Advanced Webhook Filtering

```javascript
// webhook-filter.js - Node.js webhook processor with advanced filtering
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

const JIRA_URL = 'https://jira.example.com';
const JIRA_TOKEN = process.env.JIRA_TOKEN;

// CVE severity to Jira priority mapping
const PRIORITY_MAP = {
  'Critical': 'Highest',
  'High': 'High',
  'Medium': 'Medium',
  'Low': 'Low'
};

app.post('/webhook/harbor/scan', async (req, res) => {
  const event = req.body;

  if (event.type === 'harbor.scanning.completed') {
    const { repository, tag, scan_overview } = event.data;
    const summary = scan_overview.summary;

    // Create Jira ticket for critical vulnerabilities
    if (summary.Critical > 0) {
      const ticket = {
        fields: {
          project: { key: 'SEC' },
          summary: `Critical CVEs in ${repository}:${tag}`,
          description: formatDescription(event.data),
          issuetype: { name: 'Security Issue' },
          priority: { name: 'Highest' },
          labels: ['harbor', 'cve', 'critical']
        }
      };

      await axios.post(`${JIRA_URL}/rest/api/2/issue`, ticket, {
        headers: {
          'Authorization': `Bearer ${JIRA_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });
    }
  }

  res.status(200).json({ status: 'ok' });
});

function formatDescription(data) {
  return `
Image: ${data.repository}:${data.tag}
Total CVEs: ${data.scan_overview.total_count}
Fixable: ${data.scan_overview.fixable_count}

Severity Breakdown:
- Critical: ${data.scan_overview.summary.Critical || 0}
- High: ${data.scan_overview.summary.High || 0}
- Medium: ${data.scan_overview.summary.Medium || 0}
- Low: ${data.scan_overview.summary.Low || 0}

Scan completed at: ${data.scan_overview.end_time}
  `.trim();
}

app.listen(8080, () => console.log('Webhook processor running on port 8080'));
```

---

## 5. CVE Reporting and Metrics

### Generate Compliance Reports

```python
#!/usr/bin/env python3
# generate-cve-report.py - Generate vulnerability compliance report

import requests
from requests.auth import HTTPBasicAuth
import csv
from datetime import datetime
import os

HARBOR_URL = "https://harbor.example.com"
USERNAME = "admin"
PASSWORD = os.environ["HARBOR_PASSWORD"]

auth = HTTPBasicAuth(USERNAME, PASSWORD)

def get_all_artifacts(project):
    """Retrieve all artifacts from a project"""
    artifacts = []
    repos_url = f"{HARBOR_URL}/api/v2.0/projects/{project}/repositories"
    repos = requests.get(repos_url, auth=auth).json()

    for repo in repos:
        repo_name = repo["name"].split("/", 1)[1]
        artifacts_url = f"{HARBOR_URL}/api/v2.0/projects/{project}/repositories/{repo_name}/artifacts"
        repo_artifacts = requests.get(artifacts_url, auth=auth).json()

        for artifact in repo_artifacts:
            artifact["project"] = project
            artifact["repository"] = repo_name
            artifacts.append(artifact)

    return artifacts

def generate_report(projects, output_file):
    """Generate CSV report of vulnerabilities"""
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['project', 'repository', 'tag', 'digest', 'signed',
                      'critical', 'high', 'medium', 'low', 'total', 'fixable',
                      'scan_time', 'compliant']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for project in projects:
            artifacts = get_all_artifacts(project)

            for artifact in artifacts:
                tags = [t["name"] for t in artifact.get("tags", [])]
                tag = tags[0] if tags else "untagged"
                digest = artifact["digest"][:12]

                # Get scan overview
                scan = artifact.get("scan_overview", {})
                trivy_scan = scan.get("application/vnd.security.vulnerability.report; version=1.1", {})
                summary = trivy_scan.get("summary", {})

                # Check if signed
                signed = len(artifact.get("accessories", [])) > 0

                # Determine compliance
                critical = summary.get("Critical", 0)
                high = summary.get("High", 0)
                compliant = critical == 0 and high == 0 and signed

                writer.writerow({
                    'project': project,
                    'repository': artifact["repository"],
                    'tag': tag,
                    'digest': digest,
                    'signed': signed,
                    'critical': critical,
                    'high': high,
                    'medium': summary.get("Medium", 0),
                    'low': summary.get("Low", 0),
                    'total': trivy_scan.get("total_count", 0),
                    'fixable': trivy_scan.get("fixable_count", 0),
                    'scan_time': trivy_scan.get("end_time", "Never"),
                    'compliant': compliant
                })

if __name__ == "__main__":
    projects = ["production", "staging", "library"]
    output_file = f"harbor-cve-report-{datetime.now().strftime('%Y%m%d')}.csv"
    generate_report(projects, output_file)
    print(f"Report generated: {output_file}")
```

### Track CVE Metrics

```bash
#!/bin/bash
# cve-metrics.sh - Calculate vulnerability metrics

HARBOR_URL="https://harbor.example.com"
PROJECT="production"

# Get all artifacts with scan results
ARTIFACTS=$(curl -s "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories" \
  -u "admin:${HARBOR_PASSWORD}" | jq -r '.[].name' | \
  while read REPO; do
    REPO_NAME=$(echo $REPO | cut -d'/' -f2)
    curl -s "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories/${REPO_NAME}/artifacts" \
      -u "admin:${HARBOR_PASSWORD}"
  done)

# Calculate metrics
TOTAL_ARTIFACTS=$(echo "$ARTIFACTS" | jq -s 'add | length')
SCANNED_ARTIFACTS=$(echo "$ARTIFACTS" | jq -s 'add | [.[] | select(.scan_overview != null)] | length')
CRITICAL_VULNS=$(echo "$ARTIFACTS" | jq -s 'add | [.[] | .scan_overview.summary.Critical // 0] | add')
HIGH_VULNS=$(echo "$ARTIFACTS" | jq -s 'add | [.[] | .scan_overview.summary.High // 0] | add')
SIGNED_ARTIFACTS=$(echo "$ARTIFACTS" | jq -s 'add | [.[] | select(.accessories != null and (.accessories | length > 0))] | length')

echo "=== Harbor CVE Metrics for ${PROJECT} ==="
echo "Total Artifacts: ${TOTAL_ARTIFACTS}"
echo "Scanned: ${SCANNED_ARTIFACTS}"
echo "Signed: ${SIGNED_ARTIFACTS}"
echo "Critical Vulnerabilities: ${CRITICAL_VULNS}"
echo "High Vulnerabilities: ${HIGH_VULNS}"
echo "Scan Coverage: $(( SCANNED_ARTIFACTS * 100 / TOTAL_ARTIFACTS ))%"
echo "Signature Coverage: $(( SIGNED_ARTIFACTS * 100 / TOTAL_ARTIFACTS ))%"
```

---

## 6. Integration with CI/CD

### GitHub Actions Integration

```yaml
# .github/workflows/harbor-scan.yml
name: Harbor Scan and Policy Check

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Login to Harbor
        uses: docker/login-action@v3
        with:
          registry: harbor.example.com
          username: ${{ secrets.HARBOR_USERNAME }}
          password: ${{ secrets.HARBOR_PASSWORD }}

      - name: Build image
        run: |
          docker build -t harbor.example.com/library/app:${{ github.sha }} .

      - name: Push to Harbor
        run: |
          docker push harbor.example.com/library/app:${{ github.sha }}

      - name: Wait for scan completion
        run: |
          SCAN_STATUS="pending"
          ATTEMPTS=0
          MAX_ATTEMPTS=60

          while [ "$SCAN_STATUS" != "Success" ] && [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
            sleep 10
            SCAN_STATUS=$(curl -s -u "${{ secrets.HARBOR_USERNAME }}:${{ secrets.HARBOR_PASSWORD }}" \
              "https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/${{ github.sha }}" | \
              jq -r '.scan_overview | to_entries[0].value.scan_status // "pending"')
            echo "Scan status: $SCAN_STATUS"
            ATTEMPTS=$((ATTEMPTS + 1))
          done

          if [ "$SCAN_STATUS" != "Success" ]; then
            echo "Scan did not complete in time"
            exit 1
          fi

      - name: Check vulnerabilities
        run: |
          CRITICAL=$(curl -s -u "${{ secrets.HARBOR_USERNAME }}:${{ secrets.HARBOR_PASSWORD }}" \
            "https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/${{ github.sha }}" | \
            jq -r '.scan_overview | to_entries[0].value.summary.Critical // 0')

          HIGH=$(curl -s -u "${{ secrets.HARBOR_USERNAME }}:${{ secrets.HARBOR_PASSWORD }}" \
            "https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/${{ github.sha }}" | \
            jq -r '.scan_overview | to_entries[0].value.summary.High // 0')

          echo "Critical vulnerabilities: $CRITICAL"
          echo "High vulnerabilities: $HIGH"

          if [ $CRITICAL -gt 0 ]; then
            echo "CRITICAL vulnerabilities detected, blocking deployment"
            exit 1
          fi

          if [ $HIGH -gt 5 ]; then
            echo "Too many HIGH vulnerabilities detected, blocking deployment"
            exit 1
          fi
```

---

## Summary

This reference provides production-ready patterns for:
- **Trivy Integration**: Complete scanner setup and configuration
- **CVE Policies**: Multi-tier severity enforcement and exemption management
- **Automated Scanning**: Scan-on-push, scheduled rescans, bulk operations
- **Webhook Automation**: Event-driven security notifications and ticket creation
- **Compliance Reporting**: CVE metrics, vulnerability tracking, audit reports
- **CI/CD Integration**: GitHub Actions workflows with scan verification

Use these patterns to implement comprehensive vulnerability management that protects your container supply chain while maintaining developer velocity.
