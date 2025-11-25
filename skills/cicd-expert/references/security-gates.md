# CI/CD Security Gates & Best Practices

This file contains comprehensive security implementation guidance for CI/CD pipelines.

---

## Table of Contents

1. [OWASP CI/CD Security Risks](#owasp-cicd-security-risks)
2. [SAST Integration](#sast-integration)
3. [DAST Integration](#dast-integration)
4. [SCA (Dependency Scanning)](#sca-dependency-scanning)
5. [Container Security](#container-security)
6. [Secrets Management](#secrets-management)
7. [Artifact Signing & Provenance](#artifact-signing--provenance)
8. [Infrastructure as Code Scanning](#infrastructure-as-code-scanning)
9. [Security Policy Enforcement](#security-policy-enforcement)

---

## OWASP CI/CD Security Risks

### CICD-SEC-1: Insufficient Flow Control Mechanisms

**Risk**: Attackers can manipulate pipeline flow to bypass security gates or inject malicious code.

**Impact**: Critical - Can lead to supply chain compromise, unauthorized deployments.

**Mitigation**:

```yaml
# GitHub Actions - Branch Protection
# Configure via GitHub Settings > Branches > Add rule

# Required in .github/workflows/main.yml
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Gate 1: Required security checks
      - name: Security scan
        run: semgrep --config=p/security-audit --error

      # Gate 2: Required code review (enforced by branch protection)
      # Gate 3: Required status checks
      - name: Tests
        run: npm test

# GitLab - Protected Branches
# Settings > Repository > Protected Branches
# - Allowed to merge: Maintainers
# - Allowed to push: No one
# - Require approval: 2 approvals
```

**GitHub Branch Protection Rules**:
- ✅ Require pull request before merging
- ✅ Require approvals (minimum 2)
- ✅ Dismiss stale pull request approvals
- ✅ Require review from Code Owners
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ✅ Require conversation resolution
- ✅ Require signed commits
- ✅ Include administrators

---

### CICD-SEC-2: Inadequate Identity and Access Management

**Risk**: Overly permissive service accounts, static credentials, lack of least privilege.

**Impact**: Critical - Credential theft, lateral movement, unauthorized access.

**Mitigation**:

#### Use OIDC Instead of Static Credentials

```yaml
# GitHub Actions - OIDC for AWS
name: Deploy

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1
          # No static credentials needed!

      - name: Deploy to S3
        run: aws s3 sync ./dist s3://my-bucket
```

**AWS IAM Policy for GitHub OIDC**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
        }
      }
    }
  ]
}
```

#### Minimal Permissions per Job

```yaml
# GitHub Actions - Minimal permissions
permissions:
  contents: read  # Only read repository contents
  packages: write  # Only write packages
  # NO other permissions!

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps: [...]

  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps: [...]
```

---

### CICD-SEC-3: Dependency Chain Abuse

**Risk**: Malicious dependencies, vulnerable libraries, supply chain attacks.

**Impact**: High - Code execution, data exfiltration, backdoors.

**Mitigation**:

```yaml
# GitHub Actions - Comprehensive SCA
name: Dependency Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily scans

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0

  snyk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=all

      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: snyk.sarif

  sbom-generation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

**Dependency Pinning**:

```json
// package.json - Pin exact versions
{
  "dependencies": {
    "express": "4.18.2",  // ✅ Exact version
    "react": "^18.2.0"    // ❌ Allows minor updates
  }
}
```

```yaml
# Dockerfile - Pin base images to digest
FROM node:20-alpine@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666

# requirements.txt - Pin exact versions
requests==2.31.0
flask==3.0.0
```

---

### CICD-SEC-4: Poisoned Pipeline Execution (PPE)

**Risk**: Attackers modify pipeline configuration to execute malicious code.

**Impact**: Critical - Complete CI/CD compromise, supply chain attack.

**Mitigation**:

```yaml
# Separate pipeline definition from code
# Store pipeline in protected branch, code in feature branches

# .github/workflows/secure-pr.yml
name: Secure PR Build

on:
  pull_request_target:  # Runs in context of base branch
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      # Checkout PR code (untrusted)
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # Run security scans BEFORE any code execution
      - name: Scan for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}

      - name: SAST scan
        uses: semgrep/semgrep-action@v1
        with:
          config: p/security-audit

      # Only if scans pass, run build
      - name: Build
        if: success()
        run: npm ci && npm run build

      # NEVER use secrets in pull_request_target
      # NEVER run untrusted code with elevated permissions
```

**GitLab - Separate Trusted/Untrusted Pipelines**:

```yaml
# .gitlab-ci.yml
variables:
  FF_USE_LEGACY_BUILDS_DIR_FOR_DOCKER: "false"

# Trusted pipeline (on main)
.trusted-template:
  only:
    refs:
      - main
  except:
    refs:
      - merge_requests

# Untrusted pipeline (on MRs)
.untrusted-template:
  only:
    refs:
      - merge_requests
  except:
    refs:
      - main

security-scan:
  extends: .untrusted-template
  script:
    - semgrep --config=p/security-audit

deploy:
  extends: .trusted-template
  script:
    - kubectl apply -f k8s/
```

---

### CICD-SEC-6: Insufficient Credential Hygiene

**Risk**: Secrets in logs, hardcoded credentials, no rotation, excessive scope.

**Impact**: Critical - Credential theft, unauthorized access.

**Mitigation**:

#### Secrets Scanning

```yaml
# Pre-commit hook - .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

# GitHub Actions
name: Secrets Scan

on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

#### Vault Integration

```yaml
# GitHub Actions - HashiCorp Vault
name: Deploy with Vault

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Import secrets from Vault
        uses: hashicorp/vault-action@v2
        with:
          url: https://vault.example.com
          method: jwt
          role: github-actions
          secrets: |
            secret/data/production/db username | DB_USERNAME ;
            secret/data/production/db password | DB_PASSWORD ;
            secret/data/production/api-keys stripe | STRIPE_API_KEY

      - name: Deploy
        run: ./deploy.sh
        env:
          DB_USERNAME: ${{ env.DB_USERNAME }}
          DB_PASSWORD: ${{ env.DB_PASSWORD }}
          STRIPE_API_KEY: ${{ env.STRIPE_API_KEY }}
```

#### Secret Masking

```yaml
# Automatically mask secrets in logs
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Use secret safely
        run: |
          # Mask custom values
          echo "::add-mask::${{ secrets.API_KEY }}"
          echo "::add-mask::$CUSTOM_SECRET"

          # Safe to log
          echo "API_KEY is configured"

          # NEVER do this:
          # echo "API_KEY=${{ secrets.API_KEY }}"  # ❌ Exposed in logs!
```

---

## SAST Integration

### Semgrep

```yaml
# .github/workflows/sast-semgrep.yml
name: SAST - Semgrep

on:
  pull_request:
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config=p/security-audit \
            --config=p/owasp-top-ten \
            --config=p/ci \
            --config=p/secrets \
            --sarif \
            --output=semgrep.sarif \
            --error

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif

# Custom Semgrep rules - .semgrep.yml
rules:
  - id: hardcoded-secret
    pattern: |
      password = "..."
    message: Hardcoded password detected
    severity: ERROR
    languages: [python, javascript]

  - id: sql-injection
    pattern: |
      db.execute(f"SELECT * FROM users WHERE id = {$USER_INPUT}")
    message: SQL injection vulnerability
    severity: ERROR
    languages: [python]
```

### CodeQL

```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [javascript, python, go]

    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: ${{ matrix.language }}
          queries: security-extended,security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@v2

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
        with:
          category: "/language:${{ matrix.language }}"
```

### SonarQube

```yaml
# .github/workflows/sonarqube.yml
name: SonarQube Analysis

on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis

      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

      - name: SonarQube Quality Gate
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

---

## DAST Integration

### OWASP ZAP

```yaml
# .github/workflows/dast-zap.yml
name: DAST - OWASP ZAP

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly scans
  workflow_dispatch:

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start application
        run: |
          docker-compose up -d
          sleep 30  # Wait for app to start

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'

      - name: ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:8000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-j'

      - name: Upload ZAP results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: zap_results.sarif

      - name: Cleanup
        if: always()
        run: docker-compose down
```

**ZAP Rules Configuration** (`.zap/rules.tsv`):

```tsv
# Rule	Threshold	Action
10020	MEDIUM	IGNORE	# X-Frame-Options (handled by CDN)
10021	MEDIUM	IGNORE	# X-Content-Type-Options (handled by CDN)
10096	HIGH	FAIL	# Timestamp Disclosure
10098	MEDIUM	WARN	# Cross-Domain JavaScript Source File Inclusion
```

---

## SCA (Dependency Scanning)

### Snyk

```yaml
# .github/workflows/sca-snyk.yml
name: SCA - Snyk

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'

jobs:
  snyk-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --all-projects --severity-threshold=high

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: snyk.sarif

  snyk-container:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:latest .

      - name: Scan container image
        uses: snyk/actions/docker@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          image: myapp:latest
          args: --severity-threshold=high
```

### Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  # npm dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    versioning-strategy: increase

  # Docker dependencies
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers:
      - "devops-team"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## Container Security

### Trivy Scanning

```yaml
# .github/workflows/container-scan.yml
name: Container Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Scan filesystem
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'table'
          severity: 'CRITICAL,HIGH'
```

### Grype Scanning

```yaml
# Alternative: Grype scanner
- name: Scan image with Grype
  uses: anchore/scan-action@v3
  with:
    image: myapp:${{ github.sha }}
    fail-build: true
    severity-cutoff: high
    output-format: sarif

- name: Upload results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: ${{ steps.scan.outputs.sarif }}
```

---

## Artifact Signing & Provenance

### Cosign (Sigstore)

```yaml
# .github/workflows/sign-artifacts.yml
name: Sign Artifacts

on:
  push:
    branches: [main]
    tags: ['v*']

permissions:
  packages: write
  id-token: write
  contents: read

jobs:
  build-sign-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          outputs: type=image,name=ghcr.io/${{ github.repository }},push-by-digest=true,name-canonical=true

      - name: Sign container image
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

      - name: Verify signature
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}/*" \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
          format: cyclonedx-json
          output-file: sbom.json

      - name: Attest SBOM
        run: |
          cosign attest --yes \
            --predicate sbom.json \
            --type cyclonedx \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

---

## Infrastructure as Code Scanning

### Checkov

```yaml
# .github/workflows/iac-scan.yml
name: IaC Security Scan

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'k8s/**'
      - 'cloudformation/**'

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform,kubernetes,cloudformation
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: checkov.sarif
```

### tfsec

```yaml
# Terraform-specific security scanner
- name: tfsec
  uses: aquasecurity/tfsec-action@v1.0.0
  with:
    working_directory: terraform/
    soft_fail: false
    format: sarif
    additional_args: --minimum-severity HIGH
```

---

## Security Policy Enforcement

### Open Policy Agent (OPA)

```yaml
# .github/workflows/policy-check.yml
name: Policy Enforcement

jobs:
  opa-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/

      - name: Test Kubernetes manifests
        run: |
          opa test k8s/policies/*.rego

      - name: Validate manifests against policy
        run: |
          opa eval -d k8s/policies/ -d k8s/manifests/ \
            --format pretty \
            "data.kubernetes.admission.deny"
```

**Example OPA Policy** (`k8s/policies/security.rego`):

```rego
package kubernetes.admission

deny[msg] {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg = "Containers must not run as root"
}

deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container %v must set allowPrivilegeEscalation to false", [container.name])
}

deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.image
    not contains(container.image, "@sha256:")
    msg = sprintf("Container %v must use image digest instead of tag", [container.name])
}
```

---

## Complete Security Pipeline Example

```yaml
# .github/workflows/complete-security.yml
name: Complete Security Pipeline

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  id-token: write

jobs:
  # Gate 1: Secrets Scanning
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2

      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  # Gate 2: SAST
  sast:
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/security-audit

      - name: CodeQL
        uses: github/codeql-action/analyze@v2

  # Gate 3: SCA
  sca:
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4

      - name: Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

  # Gate 4: Build & Test
  build:
    runs-on: ubuntu-latest
    needs: [sast, sca]
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build && npm test

  # Gate 5: Container Scan
  container-scan:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        uses: docker/build-push-action@v5
        with:
          context: .
          load: true
          tags: myapp:${{ github.sha }}

      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

  # Gate 6: IaC Scan
  iac-scan:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4

      - name: Checkov
        uses: bridgecrewio/checkov-action@master

  # Gate 7: Sign & Push
  sign-push:
    runs-on: ubuntu-latest
    needs: [container-scan, iac-scan]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Sign image
        run: cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

  # Final Gate: Deploy
  deploy:
    runs-on: ubuntu-latest
    needs: sign-push
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - name: Deploy
        run: echo "Deploy to production"
```

---

## Best Practices Summary

### ✅ DO

- Run security scans on every PR and push
- Pin all dependencies to exact versions or digests
- Use OIDC instead of static credentials
- Sign all artifacts with Cosign
- Generate and verify SBOMs
- Implement branch protection rules
- Separate trusted and untrusted pipeline execution
- Mask secrets in logs
- Scan for secrets before code execution
- Use minimal permissions for workflows
- Implement security gates that block on failure
- Rotate credentials regularly
- Monitor security alerts and act on them

### ❌ DON'T

- Skip security scans to "move faster"
- Use `pull_request_target` with untrusted code
- Expose secrets to fork PRs
- Hardcode credentials anywhere
- Use overly permissive IAM roles
- Allow unsigned or unverified artifacts in production
- Ignore security vulnerabilities
- Use latest tags without verification
- Disable security features without approval
- Run production deployments without review

---

## Additional Resources

- **OWASP CI/CD Security**: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- **Sigstore Documentation**: https://docs.sigstore.dev/
- **GitHub Security Best Practices**: https://docs.github.com/en/actions/security-guides
- **SLSA Framework**: https://slsa.dev/
- **Supply Chain Levels for Software Artifacts**: https://slsa.dev/spec/v1.0/
