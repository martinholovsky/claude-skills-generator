# Security Auditing Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect

1. **Audit Log Integrity** - Sensitivity: CRITICAL
2. **Log Confidentiality** - Sensitivity: HIGH
3. **SIEM Availability** - Sensitivity: HIGH
4. **Compliance Evidence** - Sensitivity: HIGH

### Threat Actors

1. **Attackers Covering Tracks** - Delete/modify logs
2. **Malicious Insiders** - Forge audit entries
3. **Compliance Violators** - Disable logging

---

## Attack Scenario 1: Log Tampering to Hide Breach

**Threat Category**: CWE-117 - Improper Output Neutralization for Logs

**Threat Level**: CRITICAL

**Attack Description**:
Attacker modifies or deletes logs to hide malicious activity.

**Attack Flow**:
```
1. Attacker gains access to system
2. Performs malicious actions (data exfiltration)
3. Locates audit log files
4. Deletes incriminating entries
5. Breach goes undetected
6. No evidence for incident response
```

**Impact**:
- **Confidentiality**: HIGH - Attack details hidden
- **Integrity**: CRITICAL - Evidence destroyed
- **Availability**: MEDIUM - Investigation hampered
- **Business**: Regulatory violations, undetected breach

**Mitigation**:
```python
# 1. Tamper-evident logging with hash chain
class TamperEvidentLog:
    def write(self, entry):
        entry['previous_hash'] = self._previous_hash
        entry_hash = hashlib.sha256(json.dumps(entry).encode()).digest()
        entry['hash'] = entry_hash.hex()
        entry['signature'] = hmac.new(self._key, ...).hexdigest()
        self._previous_hash = entry_hash

# 2. WORM storage
# Use append-only filesystem attributes
# chattr +a /var/log/audit.log

# 3. Real-time forwarding to SIEM
# Logs are immediately copied to secure location
siem_forwarder.send(entry)

# 4. Falco detection rule
# Detect log file deletion attempts
```

---

## Attack Scenario 2: Log Injection

**Threat Category**: CWE-117 - Improper Output Neutralization for Logs

**Threat Level**: HIGH

**Attack Description**:
Attacker injects malicious content into logs to forge entries or exploit log viewers.

**Attack Flow**:
```
1. Attacker controls user input field
2. Injects newline + fake log entry:
   "normal data\n2024-01-01 Admin logged in from 127.0.0.1"
3. Fake entry appears in logs
4. Attackers actions attributed to admin
5. Or: inject XSS payload for log viewer
```

**Mitigation**:
```python
# 1. Structured logging (JSON)
# Newlines are escaped in JSON strings
logger.info("event", user_input=malicious_data)
# Output: {"event": "event", "user_input": "normal\\nfake entry"}

# 2. Input validation
def sanitize_for_log(value: str) -> str:
    """Remove control characters from log values."""
    return ''.join(
        c for c in value
        if c.isprintable() or c in ' \t'
    )

# 3. Escape for output context
# HTML-escape if logs viewed in browser
```

**Testing**:
```python
def test_log_injection_prevented():
    malicious = 'normal\n{"fake": "entry"}\r\nmore'

    audit.log("test", user_input=malicious)

    with open(log_path) as f:
        lines = f.readlines()

    # Should be single line
    assert len(lines) == 1

    # Malicious content should be in value, not structure
    entry = json.loads(lines[0])
    assert entry['user_input'] == malicious
```

---

## Attack Scenario 3: SIEM Flooding/Evasion

**Threat Category**: CWE-400 - Uncontrolled Resource Consumption

**Threat Level**: MEDIUM

**Attack Description**:
Attacker floods SIEM with noise to hide malicious events or cause alert fatigue.

**Attack Flow**:
```
1. Attacker generates massive log volume
2. SIEM overwhelmed with events
3. Legitimate security alerts lost
4. Analysts experience alert fatigue
5. Malicious activity goes unnoticed
```

**Mitigation**:
```python
# 1. Rate limiting on log generation
from functools import lru_cache
import time

class RateLimitedLogger:
    def __init__(self, max_per_second: int = 100):
        self._max_rate = max_per_second
        self._count = 0
        self._window_start = time.time()

    def log(self, event):
        current = time.time()
        if current - self._window_start >= 1:
            self._count = 0
            self._window_start = current

        if self._count >= self._max_rate:
            # Log rate limit exceeded (once)
            return

        self._count += 1
        self._do_log(event)

# 2. Aggregation at source
# Combine similar events
class EventAggregator:
    def aggregate(self, events):
        """Combine repeated events into single entry with count."""
        pass

# 3. SIEM-side deduplication and correlation
```

---

## Attack Scenario 4: PII Exposure in Logs

**Threat Category**: CWE-532 - Insertion of Sensitive Information into Log File

**Threat Level**: HIGH

**Attack Description**:
Sensitive data accidentally logged, creating compliance violation and data exposure.

**Attack Flow**:
```
1. Developer logs full request for debugging
2. Request contains password/token/PII
3. Logs stored without encryption
4. Unauthorized access to logs
5. PII exposed - GDPR violation
```

**Mitigation**:
```python
# 1. PII scrubbing
class PIIScrubber:
    PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]'),
        (r'\bpassword["\']?\s*[:=]\s*["\']?[^"\'}\s]+', 'password=[REDACTED]'),
    ]

    def scrub(self, text: str) -> str:
        for pattern, replacement in self.PATTERNS:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text

# 2. Allowlist approach
ALLOWED_FIELDS = {'user_id', 'action', 'resource', 'timestamp', 'outcome'}

def safe_log(event: dict):
    """Log only allowed fields."""
    safe_event = {k: v for k, v in event.items() if k in ALLOWED_FIELDS}
    logger.info(safe_event)

# 3. Automated scanning
def scan_logs_for_pii(log_path: str):
    """Scan logs for PII violations."""
    violations = []
    # Check for patterns
    return violations
```

---

## Attack Scenario 5: SIEM Credential Compromise

**Threat Category**: CWE-522 - Insufficiently Protected Credentials

**Threat Level**: HIGH

**Attack Description**:
SIEM API token compromised, allowing attacker to read all security logs.

**Attack Flow**:
```
1. SIEM token stored insecurely
2. Attacker obtains token
3. Queries SIEM for all security events
4. Maps entire security posture
5. Plans targeted attack based on blind spots
```

**Mitigation**:
```python
# 1. Store SIEM token in OS keychain
from jarvis.security.os_keychain import SecureCredentialStore

keychain = SecureCredentialStore("siem")
token = keychain.retrieve("splunk-hec-token")

# 2. Use short-lived tokens
# Rotate SIEM tokens regularly

# 3. Limit token permissions
# Token should only have write access, not read

# 4. Monitor SIEM access
# Alert on unusual query patterns
```

---

## STRIDE Analysis

| Category | Threat | Mitigation | Priority |
|----------|--------|------------|----------|
| **Spoofing** | Forged log entries | Cryptographic signatures | HIGH |
| **Tampering** | Log modification | Hash chains, WORM storage | CRITICAL |
| **Repudiation** | Deny actions | Tamper-evident audit trail | HIGH |
| **Information Disclosure** | PII in logs | Scrubbing, encryption | HIGH |
| **Denial of Service** | Log flooding | Rate limiting, aggregation | MEDIUM |
| **Elevation of Privilege** | SIEM admin access | Least privilege, MFA | HIGH |

---

## Security Controls Summary

### Log Integrity
- [ ] Cryptographic signing of entries
- [ ] Hash chain linking
- [ ] WORM storage
- [ ] Real-time SIEM forwarding

### Log Confidentiality
- [ ] PII scrubbing
- [ ] Log encryption at rest
- [ ] Access control on log files
- [ ] SIEM token protection

### Log Availability
- [ ] Multiple log destinations
- [ ] Log rotation and retention
- [ ] Backup procedures
- [ ] Monitoring for log gaps

### Detection
- [ ] Falco rules for log tampering
- [ ] Alert on log deletion attempts
- [ ] Monitor for log gaps
- [ ] SIEM health monitoring
