# Encryption Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect

1. **Encryption Keys** - Sensitivity: CRITICAL
   - Master keys, key encryption keys, data encryption keys
   - Compromise = complete confidentiality loss

2. **Encrypted Data** - Sensitivity: HIGH
   - User credentials, API keys, personal data
   - Protected by encryption but vulnerable to key compromise

3. **Key Derivation Parameters** - Sensitivity: MEDIUM
   - Salts, iteration counts, algorithm configurations
   - Exposure enables targeted attacks

### Threat Actors

1. **External Attackers** - Financial gain, data theft
2. **Malicious Insiders** - Privileged access abuse
3. **Nation-State Actors** - Advanced persistent threats
4. **Supply Chain Attackers** - Compromised dependencies

### Attack Surface

- Key derivation functions
- Random number generation
- Memory handling
- Cryptographic libraries
- Key storage mechanisms
- Ciphertext integrity

---

## Attack Scenario 1: Weak Key Derivation

**Threat Category**: CWE-916 - Use of Password Hash With Insufficient Computational Effort

**Threat Level**: CRITICAL

**Attack Description**:
Attacker obtains encrypted database and brute-forces the password due to insufficient KDF parameters.

**Attack Flow**:
```
1. Attacker steals encrypted SQLCipher database file
2. Attacker identifies weak PBKDF2 configuration (1000 iterations)
3. Attacker uses GPU cluster to test passwords at 10M/second
4. Common passwords cracked within hours
5. Database decrypted, all data exposed
```

**Impact**:
- **Confidentiality**: CRITICAL - All encrypted data exposed
- **Integrity**: HIGH - Data can be modified
- **Availability**: LOW - Original data intact
- **Business**: Data breach, regulatory fines, reputation damage

**Likelihood**: HIGH - Default configurations often weak

**Mitigation**:

```python
# Use Argon2id with memory-hard parameters
from argon2.low_level import hash_secret_raw, Type

key = hash_secret_raw(
    secret=password.encode(),
    salt=salt,
    time_cost=3,        # Iterations
    memory_cost=65536,  # 64 MiB - makes GPU attacks expensive
    parallelism=4,
    hash_len=32,
    type=Type.ID        # Argon2id - resistant to both GPU and side-channel
)
```

**Detection**:
```python
# Audit KDF configuration
def audit_kdf_config(db_path):
    conn = sqlcipher3.connect(db_path)
    kdf_iter = conn.execute("PRAGMA kdf_iter;").fetchone()[0]

    if kdf_iter < 256000:
        logger.critical(f"Weak KDF: {kdf_iter} iterations (minimum: 256000)")
        return False
    return True
```

**Testing**:
```python
def test_kdf_parameters_meet_owasp():
    """Verify KDF meets OWASP minimum requirements."""
    config = get_database_config()

    # OWASP recommends Argon2id with:
    # - 19 MiB memory minimum (we use 64 MiB)
    # - 2 iterations minimum (we use 3)
    assert config.argon2_memory >= 19456, "Memory cost too low"
    assert config.argon2_iterations >= 2, "Iteration count too low"
```

---

## Attack Scenario 2: Nonce Reuse

**Threat Category**: CWE-323 - Reusing a Nonce/IV in Encryption

**Threat Level**: CRITICAL

**Attack Description**:
Reusing nonces with AES-GCM allows attacker to recover plaintext XOR and forge authentication tags.

**Attack Flow**:
```
1. Application uses counter-based nonces
2. Server restart resets counter to 0
3. Same nonce used with same key
4. Attacker observes two ciphertexts with same nonce
5. XOR of plaintexts can be computed
6. Authentication can be forged
```

**Impact**:
- **Confidentiality**: CRITICAL - Plaintext recovery possible
- **Integrity**: CRITICAL - Forgery of valid ciphertexts
- **Availability**: LOW
- **Business**: Complete cryptographic failure

**Likelihood**: MEDIUM - Requires specific implementation errors

**Mitigation**:

```python
import secrets

class SecureEncryption:
    def encrypt(self, plaintext: bytes) -> bytes:
        # ALWAYS use cryptographically random nonces
        nonce = secrets.token_bytes(12)  # 96 bits

        # For AES-GCM, 96-bit random nonce is safe for up to 2^32 encryptions
        # with same key before birthday bound concerns
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
```

**Detection**:
```python
def test_nonce_uniqueness():
    """Verify nonces are never reused."""
    encryptor = SecureEncryption(key)
    nonces = set()

    for _ in range(100000):
        ciphertext = encryptor.encrypt(b"test")
        nonce = ciphertext[:12]

        if nonce in nonces:
            raise SecurityError("CRITICAL: Nonce reuse detected!")
        nonces.add(nonce)
```

---

## Attack Scenario 3: Authentication Tag Bypass

**Threat Category**: CWE-347 - Improper Verification of Cryptographic Signature

**Threat Level**: HIGH

**Attack Description**:
Application processes decrypted data before verifying authentication tag, exposing plaintext on tampered ciphertext.

**Attack Flow**:
```
1. Attacker intercepts encrypted message
2. Attacker modifies ciphertext without updating tag
3. Application decrypts to corrupted plaintext
4. Application uses corrupted data before tag check
5. Side effects from corrupted data expose information
```

**Impact**:
- **Confidentiality**: HIGH - Information leakage via side effects
- **Integrity**: CRITICAL - Corrupted data processed
- **Availability**: MEDIUM - Application may crash
- **Business**: Data corruption, security bypass

**Likelihood**: MEDIUM - Common implementation error

**Mitigation**:

```python
from cryptography.exceptions import InvalidTag

def decrypt_secure(self, ciphertext: bytes) -> bytes:
    """
    Decrypt with proper authentication verification.

    The cryptography library verifies the tag BEFORE returning plaintext.
    This is the correct behavior - never separate decryption from verification.
    """
    try:
        # This raises InvalidTag if authentication fails
        # Plaintext is NEVER returned on authentication failure
        return self._aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        # Log attempt but don't reveal details
        logger.warning("crypto.auth_failure", extra={'action': 'decrypt'})
        raise
```

**Testing**:
```python
def test_tampered_ciphertext_rejected():
    """Verify tampered ciphertext is always rejected."""
    encryptor = SecureEncryption(key)
    ciphertext = encryptor.encrypt(b"secret data")

    # Tamper with various positions
    for i in range(len(ciphertext)):
        tampered = bytearray(ciphertext)
        tampered[i] ^= 0xFF

        with pytest.raises(InvalidTag):
            encryptor.decrypt(bytes(tampered))
```

---

## Attack Scenario 4: Memory Disclosure

**Threat Category**: CWE-316 - Cleartext Storage of Sensitive Information in Memory

**Threat Level**: HIGH

**Attack Description**:
Attacker extracts encryption keys from process memory, crash dumps, or swap space.

**Attack Flow**:
```
1. Key loaded into memory during operation
2. System crashes or is compromised
3. Memory dump captured (cold boot, /proc/mem, debugger)
4. Attacker scans dump for key material
5. Keys extracted, all data decryptable
```

**Impact**:
- **Confidentiality**: CRITICAL - All keys exposed
- **Integrity**: HIGH - Forgery possible
- **Availability**: LOW
- **Business**: Complete security compromise

**Likelihood**: MEDIUM - Requires system access

**Mitigation**:

```python
import ctypes
import mmap
import secrets

class MemoryProtectedKey:
    """Store key with memory protection."""

    def __init__(self, key: bytes):
        # Use mmap for memory we can control
        self._size = len(key)
        self._mem = mmap.mmap(-1, self._size)
        self._mem.write(key)

    def get(self) -> bytes:
        self._mem.seek(0)
        return self._mem.read(self._size)

    def destroy(self):
        """Overwrite before releasing."""
        self._mem.seek(0)
        self._mem.write(secrets.token_bytes(self._size))
        self._mem.seek(0)
        self._mem.write(b'\x00' * self._size)
        self._mem.close()

    def __del__(self):
        self.destroy()
```

**Additional Controls**:
- Disable core dumps: `ulimit -c 0`
- Encrypt swap: Configure encrypted swap partition
- Use HSM: Keys never leave hardware
- Minimize key lifetime: Load, use, destroy

---

## Attack Scenario 5: Cryptographic Library Vulnerability

**Threat Category**: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm

**Threat Level**: HIGH

**Attack Description**:
Vulnerability in cryptographic library allows bypass or weakening of encryption.

**Attack Flow**:
```
1. CVE published for cryptographic library (e.g., OpenSSL)
2. Application uses vulnerable version
3. Attacker exploits CVE to:
   - Extract key material (CVE-2014-0160 Heartbleed)
   - Bypass authentication (CVE-2023-42811)
   - Downgrade cipher (CVE-2015-0204 FREAK)
4. Encrypted data compromised
```

**Impact**:
- **Confidentiality**: CRITICAL - Depends on CVE
- **Integrity**: HIGH - Depends on CVE
- **Availability**: MEDIUM - Depends on CVE
- **Business**: Emergency patching required

**Likelihood**: MEDIUM - Libraries regularly have CVEs

**Mitigation**:

```yaml
# CI/CD Pipeline - Automated Vulnerability Scanning
name: Security Scan
on: [push, pull_request]

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan Python dependencies
        run: |
          pip install pip-audit safety
          pip-audit --strict
          safety check --full-report

      - name: Check for crypto library CVEs
        run: |
          # Specifically check cryptographic dependencies
          pip-audit --require-hashes --desc on | \
            grep -E "cryptography|pyopenssl|argon2|pynacl" && \
            echo "Crypto dependency has vulnerability!" && exit 1 || true

      - name: Block on HIGH/CRITICAL
        run: |
          pip-audit --format json | \
            jq '.[] | select(.vulns[].fix_versions != null) | select(.vulns[].id | startswith("CVE"))' | \
            grep -q "HIGH\|CRITICAL" && exit 1 || exit 0
```

**Testing**:
```python
def test_crypto_library_versions():
    """Verify cryptographic libraries are current."""
    import cryptography
    from packaging import version

    # Minimum versions with known security fixes
    MIN_VERSIONS = {
        'cryptography': '42.0.0',  # OpenSSL 3.x
        'argon2-cffi': '23.1.0',
    }

    current = version.parse(cryptography.__version__)
    minimum = version.parse(MIN_VERSIONS['cryptography'])

    assert current >= minimum, f"cryptography {current} < {minimum}"
```

---

## STRIDE Analysis

| Category | Threat | Mitigation | Priority |
|----------|--------|------------|----------|
| **Spoofing** | Forged ciphertext | Authenticated encryption (GCM) | CRITICAL |
| **Tampering** | Modified ciphertext | Authentication tags, HMAC | CRITICAL |
| **Repudiation** | Denied encryption operations | Audit logging with integrity | MEDIUM |
| **Information Disclosure** | Key extraction, plaintext leak | Memory protection, secure KDF | CRITICAL |
| **Denial of Service** | KDF resource exhaustion | Rate limiting, resource limits | MEDIUM |
| **Elevation of Privilege** | Key access escalation | Principle of least privilege | HIGH |

---

## Security Testing Coverage

### Automated Testing
- [ ] SAST scans for hardcoded secrets
- [ ] Dependency scanning for crypto library CVEs
- [ ] Nonce uniqueness tests (100,000+ samples)
- [ ] Authentication tag verification tests
- [ ] KDF parameter validation

### Manual Testing
- [ ] Penetration testing of key storage
- [ ] Memory dump analysis for key exposure
- [ ] Timing attack analysis on KDF
- [ ] Crypto implementation review

### Continuous Monitoring
- [ ] Decryption failure alerts (potential attack)
- [ ] Key usage anomaly detection
- [ ] Library vulnerability notifications
