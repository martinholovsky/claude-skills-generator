# SQLCipher Threat Model

## Asset Identification

### Primary Assets
1. **Encrypted Database Content** - User data, credentials, sensitive information
2. **Encryption Keys** - Master key, backup keys, derived keys
3. **Key Derivation Parameters** - Salt, iteration count
4. **Database Schema** - Structure can reveal data types

### Secondary Assets
1. **Backup Files** - May contain historical data
2. **WAL/SHM Files** - Temporary data during transactions
3. **Memory** - Keys and decrypted data in RAM
4. **Logs** - May contain metadata about access patterns

---

## Threat Actors

| Actor | Motivation | Capabilities | Access Level |
|-------|------------|--------------|--------------|
| **Local Attacker** | Data theft | Physical device access | File system |
| **Malware** | Data exfiltration | Code execution | Process memory |
| **Forensic Analyst** | Investigation | Advanced tools | Disk images |
| **Insider** | Various | Application knowledge | Running application |
| **Network Attacker** | Interception | MITM capability | Network traffic |

---

## Attack Vectors & Mitigations

### 1. Brute Force Key Derivation

**Threat**: Attacker attempts to guess password/key through brute force.

**Attack Scenario**:
```python
# Attacker obtains encrypted database file
# Attempts to brute force the password
for password in wordlist:
    key = pbkdf2(password, salt, iterations)
    if try_decrypt(database, key):
        print(f"Password found: {password}")
```

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| High iteration count | `PRAGMA kdf_iter = 256000+` | High |
| Strong KDF | Argon2id instead of PBKDF2 | Very High |
| Password requirements | Min 12 chars, complexity | Medium |
| Key stretching | Additional application-level KDF | High |

**Implementation**:
```rust
// Use Argon2id with memory-hard parameters
let argon2 = Argon2::new(
    Algorithm::Argon2id,
    Version::V0x13,
    Params::new(65536, 3, 4, Some(32)).unwrap()  // 64MB memory
);
```

### 2. Memory Extraction

**Threat**: Attacker extracts encryption key from process memory.

**Attack Scenario**:
- Memory dump via debugging
- Cold boot attack
- Malware reading process memory
- Core dump after crash

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Memory security | `PRAGMA cipher_memory_security = ON` | High |
| Zeroizing wrappers | Use `Zeroizing<T>` for all keys | High |
| Memory locking | `mlock()` to prevent swapping | Medium |
| Short key lifetime | Clear cached keys after timeout | Medium |

**Implementation**:
```rust
use zeroize::Zeroizing;

// Key is automatically zeroed when dropped
let key = Zeroizing::new(derive_key(password)?);
conn.pragma_update(None, "key", key.as_str())?;
// key goes out of scope and is zeroed

// Enable SQLCipher memory security
conn.pragma_update(None, "cipher_memory_security", "ON")?;
```

### 3. Side-Channel Attacks

**Threat**: Attacker infers key material through timing or power analysis.

**Attack Scenarios**:
- Timing attacks on key comparison
- Cache timing attacks
- Power analysis during encryption

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Constant-time comparison | Use crypto libraries | High |
| SQLCipher defaults | Built-in protections | High |
| Noise addition | Random delays | Low |

### 4. Key Storage Compromise

**Threat**: Attacker obtains stored key from keychain or file.

**Attack Scenario**:
```bash
# On macOS, if not properly secured
security find-generic-password -s "myapp-encryption" -w
```

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| OS keychain | Use platform secure storage | High |
| No file storage | Never store keys in files | Critical |
| User authentication | Require auth for key access | High |
| Hardware security | TPM/Secure Enclave | Very High |

### 5. Backup Key Exposure

**Threat**: Backup files encrypted with weak or exposed keys.

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Separate backup keys | Different key for each backup | High |
| Strong backup encryption | Same strength as main | Critical |
| Key escrow | Secure storage for backup keys | High |
| Backup rotation | Delete old backups securely | Medium |

### 6. Dependency Vulnerabilities

**Threat**: CVEs in SQLite or OpenSSL compromise security.

**Recent Examples**:
- CVE-2020-27207: SQLCipher use-after-free
- CVE-2023-2650: OpenSSL DoS
- CVE-2024-0232: SQLite use-after-free

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Version monitoring | Track security advisories | Critical |
| Automated updates | CI/CD dependency updates | High |
| Vulnerability scanning | Regular SBOM scanning | High |
| Minimal dependencies | Reduce attack surface | Medium |

### 7. Unencrypted Artifacts

**Threat**: Sensitive data leaks through unencrypted temporary files.

**Attack Vectors**:
- SQLite temp files
- Crash dumps
- Swap space
- Debug logs

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Memory temp store | `PRAGMA temp_store = MEMORY` | High |
| Secure delete | `PRAGMA secure_delete = ON` | Medium |
| Log sanitization | Never log sensitive data | Critical |
| Swap encryption | OS-level full disk encryption | High |

---

## Defense in Depth Strategy

### Layer 1: Application Security
- Input validation
- Parameterized queries
- Error handling without data leakage

### Layer 2: Cryptographic Security
- Strong key derivation (Argon2id)
- AES-256 encryption
- HMAC integrity verification

### Layer 3: Key Management
- OS keychain storage
- Memory zeroization
- Key rotation capability

### Layer 4: System Security
- File permissions (600)
- Memory locking
- Swap encryption

### Layer 5: Operational Security
- Dependency monitoring
- Security logging
- Incident response plan

---

## Key Compromise Response Plan

### Immediate Actions (0-1 hour)
1. **Assess scope** - Which keys are compromised?
2. **Revoke access** - Disable compromised keys if possible
3. **Preserve evidence** - Log all access attempts

### Short-term Actions (1-24 hours)
1. **Rotate keys** - Generate new keys for all databases
2. **Re-encrypt data** - Use new keys for all data
3. **Notify users** - If user data potentially exposed
4. **Update stored keys** - Replace in all key stores

### Long-term Actions (1-7 days)
1. **Root cause analysis** - How was key compromised?
2. **Security improvements** - Prevent recurrence
3. **Audit access** - Review all historical access
4. **Documentation** - Update security procedures

### Key Rotation Procedure
```rust
// Emergency key rotation
pub fn emergency_key_rotation(
    db_path: &Path,
    compromised_key: &Zeroizing<String>,
    new_key: &Zeroizing<String>
) -> Result<()> {
    // 1. Create backup first
    let backup_path = create_timestamped_backup(db_path)?;

    // 2. Open with compromised key
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "key", compromised_key.as_str())?;

    // 3. Re-encrypt with new key
    conn.pragma_update(None, "rekey", new_key.as_str())?;

    // 4. Verify
    drop(conn);
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "key", new_key.as_str())?;
    conn.query_row("SELECT 1", [], |_| Ok(()))?;

    // 5. Update key store
    update_stored_key(new_key)?;

    // 6. Log rotation event
    log_security_event("emergency_key_rotation", "completed");

    Ok(())
}
```

---

## Security Monitoring

### Events to Log
```rust
pub enum SecurityEvent {
    KeyDerivation { user: String, success: bool },
    DatabaseOpen { path: String, success: bool },
    KeyRotation { user: String, success: bool },
    BackupCreated { path: String },
    AuthenticationFailure { attempts: u32 },
    IntegrityCheckFailed { error: String },
}

pub fn log_security_event(event: SecurityEvent) {
    match event {
        SecurityEvent::AuthenticationFailure { attempts } if attempts > 3 => {
            // Alert on potential brute force
            alert_security_team("Multiple auth failures detected");
        }
        SecurityEvent::IntegrityCheckFailed { error } => {
            // Alert on potential tampering
            alert_security_team(&format!("Database integrity check failed: {}", error));
        }
        _ => {}
    }

    // Always log to audit trail
    audit_log::record(event);
}
```

### Alerting Thresholds
| Event | Threshold | Action |
|-------|-----------|--------|
| Auth failures | 3 in 5 minutes | Lock + alert |
| Key rotation failures | Any | Alert |
| Integrity check failures | Any | Alert + investigate |
| Unknown database access | Any | Alert |

---

## Compliance Mapping

### GDPR (Article 32)
- [x] Encryption of personal data
- [x] Ability to ensure confidentiality
- [x] Ability to restore data (backups)

### HIPAA (Security Rule)
- [x] Encryption at rest
- [x] Access controls
- [x] Audit logging
- [x] Integrity controls

### PCI-DSS
- [x] Strong cryptography (AES-256)
- [x] Key management procedures
- [x] Protection of cryptographic keys
