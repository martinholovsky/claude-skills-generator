# AT-SPI2 - Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH
**Attack Surface**: System-wide accessibility, D-Bus session bus

### Assets to Protect

1. **User Credentials** - CRITICAL - Password fields, key managers
2. **System Integrity** - HIGH - Input injection prevention
3. **User Privacy** - HIGH - Screen content, application data

---

## Attack Scenario 1: Password Field Harvesting

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Enumerate all accessible objects
2. Find PASSWORD_TEXT role objects
3. Read text content
4. Exfiltrate credentials
```

**Mitigation**: Block all access to PASSWORD_TEXT role

---

## Attack Scenario 2: Input Injection to Terminals

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Find terminal emulator accessible
2. Use EditableText interface
3. Inject malicious commands
4. Execute arbitrary code
```

**Mitigation**: Block terminal applications in automation

---

## Attack Scenario 3: Keyring Access

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Target gnome-keyring or seahorse
2. Enumerate secret entries
3. Extract stored passwords
4. Exfiltrate secrets
```

**Mitigation**: Block keyring applications

---

## Attack Scenario 4: D-Bus Session Bus Exploitation

**Threat Level**: HIGH

**Attack Flow**:
```
1. Connect to session bus
2. Enumerate AT-SPI2 objects
3. Access sensitive applications
4. Extract or inject data
```

**Mitigation**: Validate D-Bus peer credentials, application filtering

---

## STRIDE Analysis

| Category | Threats | Mitigations | Priority |
|----------|---------|-------------|----------|
| **Spoofing** | Fake accessible objects | Registry validation | MEDIUM |
| **Tampering** | Modify text content | Permission tiers | HIGH |
| **Repudiation** | Deny automation | Audit logging | HIGH |
| **Information Disclosure** | Read passwords | Role blocking | CRITICAL |
| **Denial of Service** | Event flooding | Rate limiting | MEDIUM |
| **Elevation of Privilege** | Terminal access | App blocklists | CRITICAL |

---

## Security Controls

### Preventive
- PASSWORD_TEXT role blocking
- Application blocklists
- D-Bus peer validation
- Permission tier enforcement

### Detective
- Comprehensive audit logging
- D-Bus activity monitoring
- Anomaly detection

### Corrective
- Automatic rate limiting
- Session termination on violations
