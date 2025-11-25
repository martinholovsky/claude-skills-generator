# OS Keychain Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect

1. **Master Encryption Keys** - Sensitivity: CRITICAL
2. **API Credentials** - Sensitivity: HIGH
3. **Database Passwords** - Sensitivity: HIGH
4. **Access Tokens** - Sensitivity: HIGH

### Threat Actors

1. **Local Attackers** - Physical access, malware
2. **Privileged Insiders** - Administrators
3. **Remote Attackers** - Via compromised application

---

## Attack Scenario 1: Credential Manager Privilege Escalation (CVE-2023-21726)

**Threat Category**: CWE-269 - Improper Privilege Management

**Threat Level**: HIGH

**Attack Description**:
Windows Credential Manager vulnerability allows local privilege escalation through UI manipulation.

**Attack Flow**:
```
1. Attacker gains local user access
2. Exploits CVE-2023-21726 in Credential Manager UI
3. Escalates to SYSTEM privileges
4. Accesses all credentials in Credential Manager
5. Extracts master keys and API credentials
```

**Impact**:
- **Confidentiality**: CRITICAL - All credentials exposed
- **Integrity**: HIGH - Can modify stored credentials
- **Availability**: MEDIUM

**Mitigation**:
- Apply Windows Update January 2023
- Enable Credential Guard (enterprise)
- Monitor privilege escalation attempts

---

## Attack Scenario 2: macOS Keychain Local Access Bypass (CVE-2024-54490)

**Threat Category**: CWE-287 - Improper Authentication

**Threat Level**: HIGH

**Attack Description**:
Local attacker bypasses hardware security to access Keychain items without authentication.

**Attack Flow**:
```
1. Attacker with local access targets macOS < 15.2
2. Exploits missing hardware security configuration
3. Bypasses Touch ID/password requirement
4. Accesses Keychain items directly
5. Extracts stored credentials
```

**Mitigation**:
```python
# Verify macOS version
import platform

def verify_macos_security():
    version = platform.mac_ver()[0]
    major, minor = map(int, version.split('.')[:2])

    if major < 15 or (major == 15 and minor < 2):
        raise SecurityError(
            f"macOS {version} vulnerable to CVE-2024-54490. "
            "Update to 15.2 or later."
        )
```

---

## Attack Scenario 3: Linux D-Bus Credential Theft

**Threat Category**: CWE-284 - Improper Access Control

**Threat Level**: MEDIUM

**Attack Description**:
Malicious application on same session accesses Secret Service via D-Bus.

**Attack Flow**:
```
1. Malicious app installed by user
2. App connects to session D-Bus
3. Calls Secret Service API
4. Requests secrets from unlocked collection
5. Exfiltrates all stored credentials
```

**Mitigation**:
```python
# Use sandboxed applications (Flatpak)
# Flatpak filters D-Bus access

# Application-level: Verify caller identity
def verify_caller():
    """
    Note: This is limited on Linux without proper sandboxing.
    Use Flatpak portals for proper access control.
    """
    pass

# Better: Use Flatpak with portal
# Flatpak apps use xdg-desktop-portal for secret access
# which provides proper permission dialogs
```

---

## Attack Scenario 4: Memory Disclosure Attack

**Threat Category**: CWE-316 - Cleartext Storage in Memory

**Threat Level**: HIGH

**Attack Description**:
Attacker extracts credentials from process memory after retrieval from keychain.

**Attack Flow**:
```
1. Application retrieves credential from keychain
2. Credential stored in Python string (immutable)
3. Attacker dumps process memory
4. Scans dump for credential patterns
5. Extracts plaintext credentials
```

**Mitigation**:
```python
import ctypes
import gc

class SecureString:
    """Best-effort secure string handling."""

    def __init__(self, value: str):
        self._bytes = value.encode('utf-8')
        self._length = len(self._bytes)

    def get(self) -> str:
        return self._bytes.decode('utf-8')

    def clear(self):
        """Overwrite memory."""
        # Create mutable buffer
        buffer = ctypes.create_string_buffer(self._length)
        ctypes.memmove(buffer, self._bytes, self._length)
        ctypes.memset(buffer, 0, self._length)
        self._bytes = b''
        gc.collect()

    def __del__(self):
        self.clear()


# Usage
def use_credential_securely(keychain, key):
    secret = SecureString(keychain.retrieve(key))
    try:
        # Use credential
        api_call(secret.get())
    finally:
        secret.clear()
```

---

## Attack Scenario 5: Keychain Collection Left Unlocked

**Threat Category**: CWE-311 - Missing Encryption of Sensitive Data

**Threat Level**: MEDIUM

**Attack Description**:
Secret Service collection remains unlocked, allowing any application to access secrets.

**Attack Flow**:
```
1. User authenticates to unlock keyring
2. Collection remains unlocked for session
3. Malicious app runs later in session
4. App accesses all secrets without authentication
5. Credentials exfiltrated
```

**Mitigation**:
```python
class SecureSecretService:
    """Secret Service with auto-lock behavior."""

    def __init__(self, lock_timeout: int = 300):
        self._lock_timeout = lock_timeout

    def retrieve_with_autolock(self, key: str) -> str:
        """Retrieve and immediately re-lock collection."""
        with self._connection() as conn:
            collection = secretstorage.get_default_collection(conn)

            was_locked = collection.is_locked()
            if was_locked:
                collection.unlock()

            try:
                # Retrieve secret
                attrs = {'application': self._app_id, 'key': key}
                items = list(collection.search_items(attrs))
                if not items:
                    raise KeyError(key)
                return items[0].get_secret().decode('utf-8')
            finally:
                # Re-lock if we unlocked it
                if was_locked:
                    collection.lock()
```

---

## STRIDE Analysis

| Category | Threat | Mitigation | Priority |
|----------|--------|------------|----------|
| **Spoofing** | Malicious app impersonation | Code signing, app sandboxing | HIGH |
| **Tampering** | Credential modification | OS-level ACLs | MEDIUM |
| **Repudiation** | Unauthorized access denied | Audit logging | MEDIUM |
| **Information Disclosure** | Credential theft | Memory protection, auto-lock | CRITICAL |
| **Denial of Service** | Keychain unavailable | Fallback mechanisms | LOW |
| **Elevation of Privilege** | Access other users' credentials | OS updates, least privilege | CRITICAL |

---

## Security Controls Summary

### Prevention
- Keep OS updated (CVE patches)
- Use application sandboxing (Flatpak, App Sandbox)
- Enable platform security features (Credential Guard, SIP)
- Minimize credential lifetime in memory

### Detection
- Monitor credential access patterns
- Alert on unusual access frequency
- Log all credential operations

### Response
- Rotate compromised credentials immediately
- Revoke access tokens on breach detection
- Notify dependent services
