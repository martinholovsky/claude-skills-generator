# AppleScript - Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH
**Attack Surface**: Shell command execution, application control, file system

### Assets to Protect

1. **System Integrity** - CRITICAL - Prevention of malicious commands
2. **User Data** - HIGH - File system access control
3. **Application State** - MEDIUM - Prevent unauthorized automation

---

## Attack Scenario 1: Command Injection

**Threat Category**: OWASP A05:2025 - Injection
**Threat Level**: CRITICAL

**Attack Flow**:
```
1. User provides malicious input: "file.txt; rm -rf /"
2. Script interpolates directly into do shell script
3. Shell executes both commands
4. System files deleted
```

**Mitigation**: Always use `quoted form of` for all user inputs

---

## Attack Scenario 2: Privilege Escalation

**Threat Category**: OWASP A01:2025 - Broken Access Control
**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Script uses "with administrator privileges"
2. User prompted for password
3. Script gains root access
4. Installs malware or modifies system
```

**Mitigation**: Block all scripts requesting administrator privileges

---

## Attack Scenario 3: Data Exfiltration

**Threat Category**: OWASP A01:2025 - Broken Access Control
**Threat Level**: HIGH

**Attack Flow**:
```
1. Script reads sensitive files
2. Uses curl to send data externally
3. Credentials or data stolen
```

**Mitigation**: Block network commands in shell scripts

---

## Attack Scenario 4: Script Injection

**Threat Category**: OWASP A05:2025 - Injection
**Threat Level**: HIGH

**Attack Flow**:
```
1. User provides input with AppleScript code
2. Code injected into script
3. Malicious automation executed
```

**Mitigation**: Never execute user-provided script content

---

## STRIDE Analysis

| Category | Threats | Mitigations | Priority |
|----------|---------|-------------|----------|
| **Spoofing** | Fake application identity | Validate app bundle | MEDIUM |
| **Tampering** | Modify executed scripts | Script integrity check | HIGH |
| **Repudiation** | Deny script execution | Audit logging | HIGH |
| **Information Disclosure** | Read sensitive files | Path validation | HIGH |
| **Denial of Service** | Infinite loop scripts | Timeout enforcement | MEDIUM |
| **Elevation of Privilege** | Admin privileges | Block admin requests | CRITICAL |

---

## Security Controls

### Preventive
- Input sanitization with `quoted form of`
- Command allowlists
- Application blocklists
- Pattern detection for dangerous commands

### Detective
- Audit logging of all executions
- Script hash logging
- Execution time monitoring

### Corrective
- Automatic timeout termination
- Alert on blocked patterns
