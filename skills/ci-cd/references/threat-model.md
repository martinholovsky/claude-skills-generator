# CI/CD Pipeline Threat Model

## Asset Identification

### Primary Assets
1. **Signing Keys** - Code signing certificates and private keys
2. **Deployment Credentials** - Cloud provider, server access credentials
3. **Source Code** - Proprietary code and algorithms
4. **Build Artifacts** - Compiled applications, packages

### Secondary Assets
1. **Workflow Files** - Pipeline definitions
2. **Environment Variables** - Configuration data
3. **Logs** - Build and deployment logs
4. **Caches** - Build caches and dependencies

---

## Threat Actors

| Actor | Motivation | Capabilities | Access Level |
|-------|------------|--------------|--------------|
| **External Attacker** | Supply chain attack | Malicious PRs, compromised deps | Public repos |
| **Malicious Insider** | Sabotage, theft | Direct repo access | Developer |
| **Compromised Account** | Various | Valid credentials | Depends on account |
| **Nation State** | Espionage, sabotage | Advanced persistent threat | Variable |
| **Automated Bots** | Crypto mining, spam | Scripted attacks | Public repos |

---

## Attack Vectors & Mitigations

### 1. Poisoned Pipeline Execution (PPE)

**Threat**: Attacker modifies workflow file to execute malicious code with elevated privileges.

**Attack Scenarios**:
- Direct PPE: Modify workflow file in branch
- Indirect PPE: Modify files referenced by workflow (scripts, configs)
- Public PPE: PR from fork with malicious workflow changes

**CVE Example**: The GitHub Actions tj-actions/changed-files compromise (CVE-2025-30066) allowed attackers to inject malicious code through a compromised action.

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Branch protection | Require PR reviews for workflow changes | High |
| CODEOWNERS | Require security team review for .github/ | High |
| Separate permissions | Different jobs for trusted/untrusted code | Critical |
| Avoid pull_request_target | Use pull_request for untrusted code | Critical |

**Implementation**:
```yaml
# CODEOWNERS file
/.github/ @security-team

# Branch protection rules (in GitHub settings)
# - Require pull request reviews
# - Require status checks
# - Include administrators
```

### 2. Dependency Confusion / Supply Chain Attack

**Threat**: Attacker publishes malicious package with same name as internal dependency or compromises existing dependency.

**Attack Scenarios**:
- Publish malicious package to public registry with internal package name
- Compromise popular action/package
- Typosquatting on popular packages

**Recent Examples**:
- tj-actions/changed-files supply chain compromise
- ua-parser-js npm compromise
- event-stream npm compromise

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Pin by SHA | All actions pinned to commit hash | Critical |
| Private registries | Use private npm/PyPI for internal packages | High |
| Dependency review | Automated scanning on PRs | High |
| Lockfiles | Commit package-lock.json, yarn.lock | Medium |

**Implementation**:
```yaml
# Pin all actions by SHA
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608

# Use dependency review
- uses: actions/dependency-review-action@v3
  with:
    fail-on-severity: high
```

### 3. Secret Exfiltration

**Threat**: Attacker extracts secrets from pipeline logs, environment, or artifacts.

**Attack Scenarios**:
- Print secrets to logs
- Send secrets to external server
- Include secrets in build artifacts
- Access secrets through debug shells

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Secret masking | Automatic in GitHub Actions | Medium |
| Minimal secrets | Only secrets needed for job | High |
| OIDC | Use keyless auth where possible | Very High |
| Audit logs | Monitor secret access | High |

**Implementation**:
```yaml
# Use OIDC instead of long-lived credentials
permissions:
  id-token: write

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
      # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY
```

### 4. Artifact Poisoning

**Threat**: Attacker modifies build artifacts to include malicious code.

**Attack Scenarios**:
- Inject code during build process
- Replace artifacts after build
- Modify artifacts in transit
- Compromise artifact storage

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Code signing | Sign all release artifacts | Critical |
| Checksums | Generate and publish hashes | High |
| Provenance | SLSA provenance attestation | Very High |
| Isolated builds | Separate build from signing | High |

**Implementation**:
```yaml
# Generate provenance attestation
- uses: slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@v1.8.0
  with:
    go-version: 1.21
```

### 5. Credential Theft from Signing

**Threat**: Attacker steals code signing certificates/keys to sign malicious software.

**Attack Scenarios**:
- Extract certificate from workflow logs
- Access certificate store
- Steal keychain/certificate files
- Compromise HSM access

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| HSM/KMS | Store keys in hardware security modules | Very High |
| Temporary keychain | Create and destroy per-build | High |
| Limited access | Only signing job has certificate | High |
| Certificate pinning | Verify certificate before use | Medium |

### 6. Runner Compromise

**Threat**: Attacker gains persistent access to build runner.

**Attack Scenarios**:
- Exploit vulnerability in build tools
- Leave backdoor in runner environment
- Modify runner configuration
- Access shared runner resources

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Ephemeral runners | Destroy after each job | Very High |
| Container isolation | Run jobs in containers | High |
| Self-hosted security | Regular patching, monitoring | Medium |
| Job isolation | Separate permissions per job | High |

---

## Defense in Depth Strategy

### Layer 1: Repository Security
- Branch protection rules
- Required reviews for workflows
- CODEOWNERS for sensitive files
- Signed commits

### Layer 2: Workflow Security
- Explicit minimal permissions
- Environment protection rules
- Required approvals for production
- Secret scoping

### Layer 3: Dependency Security
- Pin all dependencies by hash
- Automated vulnerability scanning
- SBOM generation
- Private registries

### Layer 4: Artifact Security
- Code signing
- Checksum verification
- Provenance attestation
- Secure distribution

### Layer 5: Monitoring
- Audit logs for all actions
- Alert on unusual activity
- Secret access monitoring
- Failed build analysis

---

## Incident Response

### Compromised Action Detection
1. **Identify** - Unusual behavior, unexpected network calls
2. **Contain** - Disable workflow, rotate secrets
3. **Investigate** - Review logs, check for persistence
4. **Remediate** - Update pinned SHA, remove compromised action
5. **Document** - Update threat model, improve detection

### Leaked Secret Response
1. **Immediate** - Revoke/rotate compromised credential
2. **Assess** - Determine exposure scope
3. **Investigate** - Check for unauthorized use
4. **Prevent** - Improve secret hygiene
5. **Notify** - Alert affected parties if needed

### Compromised Artifact Response
1. **Stop** - Halt distribution immediately
2. **Identify** - Determine which versions affected
3. **Notify** - Alert users to not use affected versions
4. **Replace** - Publish clean versions
5. **Investigate** - Determine root cause

---

## Security Checklist

### Repository Level
- [ ] Branch protection on main/release branches
- [ ] Required PR reviews (2+ for sensitive changes)
- [ ] CODEOWNERS for .github directory
- [ ] Signed commits required
- [ ] Disable force push

### Workflow Level
- [ ] Explicit permissions (not write-all)
- [ ] Actions pinned by SHA
- [ ] Environments with protection rules
- [ ] Secrets scoped to environments
- [ ] No secrets in logs

### Build Level
- [ ] Dependency scanning enabled
- [ ] SAST scanning enabled
- [ ] SBOM generation
- [ ] Container scanning
- [ ] License compliance

### Release Level
- [ ] Code signing implemented
- [ ] Checksums generated
- [ ] Provenance attestation
- [ ] Secure distribution channel
- [ ] Version verification

### Monitoring Level
- [ ] Audit logs enabled
- [ ] Alerts for failed auth
- [ ] Unusual activity detection
- [ ] Secret access logging
- [ ] Regular security review
