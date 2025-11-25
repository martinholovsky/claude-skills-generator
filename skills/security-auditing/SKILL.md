# Security Auditing Skill

---
name: security-auditing
version: 1.0.0
domain: security/compliance
risk_level: HIGH
languages: [python, go, typescript]
frameworks: [structlog, opentelemetry, falco]
requires_security_review: true
compliance: [GDPR, HIPAA, PCI-DSS, SOC2, ISO27001]
last_updated: 2025-01-15
---

> **MANDATORY READING PROTOCOL**: Before implementing audit logging, read `references/advanced-patterns.md` for tamper-evident patterns and `references/threat-model.md` for log integrity attacks.

## 1. Overview

### 1.1 Purpose and Scope

This skill provides security auditing and compliance capabilities:

- **Tamper-Evident Logging**: Cryptographically signed audit trails
- **SIEM Integration**: Forward events to security monitoring systems
- **Vulnerability Assessment**: Automated security scanning and reporting
- **Compliance Reporting**: Generate audit reports for regulations

### 1.2 Risk Assessment

**Risk Level**: HIGH

**Justification**:
- Audit logs are evidence in incident investigations
- Log tampering hides attacker activity
- Compliance violations result in legal penalties
- Missing logs = blind spots in security monitoring

**Attack Surface**:
- Log injection attacks
- Log tampering/deletion
- SIEM misconfiguration
- Sensitive data in logs (PII leakage)
- Log storage exhaustion

## 2. Core Responsibilities

### 2.1 Primary Functions

1. **Generate tamper-evident audit logs** for security events
2. **Forward events to SIEM** for correlation and alerting
3. **Assess vulnerabilities** through automated scanning
4. **Produce compliance reports** for regulatory requirements
5. **Detect anomalies** in user behavior and system activity

### 2.2 Core Principles

- **TDD First**: Write tests for security checks before implementation
- **Performance Aware**: Use incremental scanning and caching for efficiency
- **NEVER** log sensitive data (passwords, PII, secrets)
- **NEVER** trust log data without integrity verification
- **ALWAYS** use structured logging (JSON)
- **ALWAYS** include correlation IDs for request tracing
- **ALWAYS** protect logs from unauthorized modification

## 3. Technology Stack

| Component | Recommended | Purpose |
|-----------|-------------|---------|
| Structured Logging | `structlog` (Python) | JSON log generation |
| Log Aggregation | Elasticsearch, Loki | Centralized storage |
| SIEM | Splunk, QRadar, Sentinel | Security monitoring |
| Integrity | Signed logs, WORM storage | Tamper evidence |
| Compliance | OpenSCAP, Prowler, Trivy | Assessment tools |

## 4. Implementation Patterns

### 4.1 Tamper-Evident Audit Logging (Summary)

```python
import hashlib
import hmac
import json
from datetime import datetime, timezone

class TamperEvidentLogger:
    """Audit logger with cryptographic integrity protection."""

    def __init__(self, signing_key: bytes, output_path: str):
        self._key = signing_key
        self._path = output_path
        self._sequence = 0
        self._previous_hash = b'\x00' * 32

    def log(self, event: str, actor: str = None, **context) -> dict:
        """Log a tamper-evident audit entry."""
        self._sequence += 1

        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sequence': self._sequence,
            'event': event,
            'actor': actor,
            'context': context,
            'previous_hash': self._previous_hash.hex(),
        }

        # Calculate and sign
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry['hash'] = hashlib.sha256(entry_bytes).hexdigest()
        entry['signature'] = hmac.new(
            self._key, entry_bytes, hashlib.sha256
        ).hexdigest()

        self._previous_hash = bytes.fromhex(entry['hash'])

        with open(self._path, 'a') as f:
            f.write(json.dumps(entry) + '\n')

        return entry
```

**📚 For complete implementation** (verification, chain validation):
- See `references/advanced-patterns.md`

### 4.2 Structured Security Logging

```python
import structlog

logger = structlog.get_logger()

class SecurityAuditLogger:
    """Security-focused audit logging."""

    @staticmethod
    def log_authentication(user_id: str, success: bool, method: str, ip: str):
        """Log authentication attempt."""
        logger.info(
            "auth.attempt",
            user_id=user_id,  # Never log email for privacy
            success=success,
            method=method,
            ip_address=ip
        )

    @staticmethod
    def log_authorization(user_id: str, resource: str, action: str, allowed: bool):
        """Log authorization decision."""
        logger.info(
            "authz.decision",
            user_id=user_id,
            resource=resource,
            action=action,
            allowed=allowed
        )

    @staticmethod
    def log_data_access(user_id: str, resource_type: str, resource_id: str, action: str):
        """Log data access for compliance."""
        logger.info(
            "data.access",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action
        )
```

**📚 For complete patterns** (decorators, context managers, SIEM integration):
- See `references/security-examples.md`

### 4.3 SIEM Integration (CEF Format)

```python
class SIEMForwarder:
    def _to_cef(self, event: dict) -> str:
        """Convert event to CEF format for SIEM ingestion."""
        severity = self._map_severity(event.get('level', 'INFO'))
        return (f"CEF:0|JARVIS|SecurityAudit|1.0|{event.get('event', 'unknown')}|"
                f"{event.get('event', 'Unknown Event')}|{severity}|"
                f"src={event.get('ip_address', '')} suser={event.get('user_id', '')}")
```

**📚 For full SIEM implementation**: See `references/security-examples.md#siem-integration`

### 4.4 Vulnerability Assessment

```python
from dataclasses import dataclass
from typing import List

@dataclass
class Vulnerability:
    id: str
    severity: str
    package: str
    fixed_version: str

class VulnerabilityScanner:
    def scan_dependencies(self, path: str) -> List[Vulnerability]:
        """Scan dependencies using pip-audit, trivy for containers."""
        pass
```

**📚 For complete scanner**: See `references/advanced-patterns.md#vulnerability-assessment`

## 5. Implementation Workflow (TDD)

### Step 1: Write Failing Test First

```python
import pytest
from security_auditing import TamperEvidentLogger, SecurityAuditLogger

class TestTamperEvidentLogger:
    def test_log_entry_contains_required_fields(self, tmp_path):
        """Each log entry must have timestamp, sequence, hash, signature."""
        logger = TamperEvidentLogger(b'test-key', str(tmp_path / 'audit.log'))
        entry = logger.log("user.login", actor="user123")
        assert all(k in entry for k in ['timestamp', 'sequence', 'hash', 'signature'])

    def test_chain_integrity_detects_tampering(self, tmp_path):
        """Tampered logs must be detected via chain validation."""
        log_path = tmp_path / 'audit.log'
        logger = TamperEvidentLogger(b'test-key', str(log_path))
        logger.log("event1", actor="user1")

        # Tamper with log file
        tampered = log_path.read_text().replace('"event1"', '"TAMPERED"')
        log_path.write_text(tampered)

        valid, errors = logger.verify_chain()
        assert not valid and len(errors) > 0

    def test_no_pii_in_log_output(self, tmp_path):
        """PII patterns must not appear in logs."""
        import re
        log_path = tmp_path / 'audit.log'
        logger = SecurityAuditLogger(str(log_path))
        logger.log_authentication(user_id="user123", success=True, method="password", ip="192.168.1.1")
        content = log_path.read_text()
        assert not re.search(r'[\w\.-]+@[\w\.-]+', content)  # No emails
```

### Step 2: Implement Minimum to Pass

```python
# Implement only what's needed to pass the tests
class TamperEvidentLogger:
    def __init__(self, signing_key: bytes, output_path: str):
        self._key, self._path = signing_key, output_path
        self._sequence, self._previous_hash = 0, b'\x00' * 32

    def log(self, event: str, actor: str = None, **context) -> dict:
        self._sequence += 1
        entry = {'timestamp': datetime.now(timezone.utc).isoformat(),
                 'sequence': self._sequence, 'event': event, 'actor': actor}
        # Add hash and signature...
        return entry
```

### Step 3: Refactor Following Patterns

After tests pass, refactor for better error handling, performance optimizations, and security hardening.

### Step 4: Run Full Verification

```bash
pytest tests/security_auditing/ -v --tb=short
pytest tests/security_auditing/ --cov=security_auditing --cov-report=term-missing
```

## 6. Performance Patterns

### 6.1 Incremental Scanning

```python
# BAD: Full scan every time
def scan_all_dependencies():
    return subprocess.run(['pip-audit', '--format=json'], capture_output=True)

# GOOD: Incremental scan based on changes
class IncrementalScanner:
    def scan_if_changed(self, requirements_path: str) -> List[Vulnerability]:
        current_hash = self._hash_file(requirements_path)
        if current_hash == self._last_hash:
            return self._load_cached_results()
        results = self._full_scan(requirements_path)
        self._save_cache(current_hash, results)
        return results
```

### 6.2 Caching Scan Results

```python
# BAD: No caching - fetch every time
def get_vulnerability_info(cve_id: str) -> dict:
    return requests.get(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

# GOOD: Cache with TTL
class VulnerabilityCache:
    def get_vulnerability(self, cve_id: str) -> dict:
        if cve_id in self._cache:
            data, timestamp = self._cache[cve_id]
            if datetime.now() - timestamp < self._ttl:
                return data
        data = self._fetch_from_api(cve_id)
        self._cache[cve_id] = (data, datetime.now())
        return data
```

### 6.3 Parallel Analysis

```python
# BAD: Sequential scanning
def scan_multiple_projects(paths: List[str]) -> List[Report]:
    return [scan_project(path) for path in paths]

# GOOD: Parallel scanning with thread pool
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_multiple_projects_parallel(paths: List[str], max_workers: int = 4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_project, p): p for p in paths}
        return [f.result() for f in as_completed(futures)]
```

### 6.4 Targeted Audits

```python
# BAD: Scan everything always
def full_security_audit(project_path: str):
    scan_dependencies(project_path)
    scan_secrets(project_path)
    scan_code_vulnerabilities(project_path)

# GOOD: Targeted scans based on changes
def targeted_security_audit(project_path: str, changed_files: List[str]):
    scans_needed = set()
    for file in changed_files:
        if file.endswith(('requirements.txt', 'package.json')):
            scans_needed.add('dependencies')
        elif file.endswith(('.env', '.yml', '.yaml')):
            scans_needed.add('secrets')
        elif file.endswith(('.py', '.js', '.ts')):
            scans_needed.add('code')
    # Only run needed scans
    return {scan: globals()[f'scan_{scan}'](project_path) for scan in scans_needed}
```

### 6.5 Resource Limits

```python
# BAD: Unbounded resource usage
def scan_large_codebase(path: str):
    for root, dirs, files in os.walk(path):
        for file in files:
            analyze_file(os.path.join(root, file))

# GOOD: Resource-bounded scanning
class BoundedScanner:
    def __init__(self, max_memory_mb: int = 512, max_files: int = 10000):
        self._max_memory = max_memory_mb * 1024 * 1024
        self._max_files = max_files

    def scan_with_limits(self, path: str):
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (self._max_memory, -1))
        files_scanned = 0
        for root, _, files in os.walk(path):
            for file in files:
                if files_scanned >= self._max_files:
                    return
                files_scanned += 1
                analyze_file(os.path.join(root, file))
```

## 7. Security Standards

### 7.1 Known Vulnerabilities

| CVE | Severity | Component | Mitigation |
|-----|----------|-----------|------------|
| CVE-2023-50960 | Critical | QRadar | Command injection - Update QRadar |
| CVE-2023-50961 | High | QRadar | Stored XSS - Update QRadar |
| CVE-2023-2976 | Medium | Guava | File exposure - Update to 32.0+ |
| CVE-2024-22365 | Medium | PAM | DoS - Update Linux PAM |
| CVE-2023-22875 | Medium | QRadar | Info disclosure - Update |

### 7.2 OWASP Mapping

| OWASP 2025 | Risk | Implementation |
|------------|------|----------------|
| A09: Security Logging Failures | Critical | Tamper-evident logs, SIEM forwarding |
| A05: Security Misconfiguration | High | Log protection, retention policies |
| A01: Broken Access Control | High | Log access auditing |

**📚 For detailed OWASP guidance**:
- See `references/security-examples.md#owasp-coverage`

### 7.3 Compliance Requirements

- **GDPR Article 30**: Records of processing activities
- **HIPAA 164.312(b)**: Audit controls
- **PCI-DSS 10**: Track all access to network resources
- **SOC2 CC7.2**: Monitor system components

## 8. Testing Requirements

```python
def test_log_integrity_tamper_detection(audit_logger):
    """Tampered logs must be detected."""
    audit_logger.log("test.event", actor="user1")

    # Tamper and verify detection
    valid, errors = audit_logger.verify_chain()
    assert not valid

def test_no_pii_in_logs(audit_logger):
    """PII must not appear in logs."""
    # Check for email, phone, SSN patterns in log output
    pass
```

**📚 For complete test suite**:
- See `references/security-examples.md#testing`

## 9. Common Mistakes

### Critical Anti-Patterns

```python
# ❌ NEVER: Log passwords, tokens, PII
logger.info(f"User {email} logged in with password {password}")
# ✅ ALWAYS: Log identifiers only
logger.info("user.login", user_id=user.id, method="password")

# ❌ NEVER: Plain text logs anyone can modify
with open('audit.log', 'a') as f:
    f.write(json.dumps(event) + '\n')
# ✅ ALWAYS: Signed, chained logs
entry['signature'] = hmac.new(key, data, hashlib.sha256).hexdigest()

# ❌ NEVER: Untraced requests
logger.info("Processing request")
# ✅ ALWAYS: Include correlation ID
logger.info("request.processing", correlation_id=request.id)
```

```bash
# ❌ chmod 644 /var/log/audit.log  # World-readable
# ✅ chmod 600 /var/log/audit.log  # Restricted
```

**📚 For complete anti-patterns**: See `references/advanced-patterns.md#anti-patterns`

## 10. Pre-Implementation Checklist

### Phase 1: Before Writing Code
- [ ] Read threat model for log integrity attacks
- [ ] Identify compliance requirements (GDPR, HIPAA, PCI-DSS)
- [ ] Design tamper-evident log format
- [ ] Plan SIEM integration architecture
- [ ] Write failing tests for security checks

### Phase 2: During Implementation
- [ ] Structured JSON logging implemented
- [ ] Tamper-evident signing enabled
- [ ] No PII/secrets in logs
- [ ] Correlation IDs in all entries
- [ ] Performance patterns applied (caching, incremental scanning)
- [ ] Resource limits configured

### Phase 3: Before Committing
- [ ] All security audit tests pass
- [ ] Log protection verified (600 permissions)
- [ ] SIEM forwarding tested
- [ ] WORM storage configured for compliance
- [ ] Retention policies enforced
- [ ] Alert rules configured
- [ ] Coverage meets minimum threshold

## 11. Summary

### Key Objectives

1. **Tamper-evident logs**: Cryptographic signing and chaining
2. **Centralized monitoring**: SIEM integration for all events
3. **Compliance ready**: Meet GDPR, HIPAA, PCI-DSS requirements
4. **Privacy protection**: No PII/secrets in logs

### References

- `references/advanced-patterns.md` - Full implementations, WORM storage
- `references/security-examples.md` - SIEM configs, compliance reports
- `references/threat-model.md` - Log integrity attack scenarios

---

**If it's not logged, it didn't happen. If logs can be tampered, you can't prove anything.**
