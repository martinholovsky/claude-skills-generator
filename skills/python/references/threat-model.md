# Python Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect
1. **User Data** - Credentials, PII, application data - **Sensitivity**: CRITICAL
2. **System Access** - File system, network, processes - **Sensitivity**: CRITICAL
3. **Database** - Application state, user records - **Sensitivity**: HIGH
4. **API Keys/Secrets** - Third-party service access - **Sensitivity**: CRITICAL

### Threat Actors
1. **External Attackers** - Injection, authentication bypass
2. **Supply Chain** - Malicious packages, compromised dependencies
3. **Insider Threats** - Unauthorized data access
4. **Automated Scanners** - Mass exploitation attempts

---

## Attack Scenario 1: SQL Injection

**Threat Category**: OWASP A03:2025 - Injection / CWE-89

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Attacker identifies input field connected to database
2. Inputs: admin' OR '1'='1'--
3. Application formats string into SQL query
4. Query: SELECT * FROM users WHERE username='admin' OR '1'='1'--'
5. Returns all users, bypassing authentication
6. Attacker gains admin access
```

**Mitigation**:
```python
# Use ORM or parameterized queries
from sqlalchemy import select

async def authenticate(db, username: str, password: str) -> User | None:
    stmt = select(User).where(User.username == username)
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user and verify_password(password, user.password_hash):
        return user
    return None
```

---

## Attack Scenario 2: Insecure Deserialization

**Threat Category**: OWASP A08:2025 - Data Integrity Failures / CWE-502

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Application accepts pickled data from user
2. Attacker crafts malicious pickle payload
3. Payload contains __reduce__ with os.system call
4. pickle.loads() executes arbitrary code
5. Attacker gains shell access
```

**Mitigation**:
```python
# Never unpickle untrusted data
# Use safe serialization formats
import json

def load_data(data: bytes) -> dict:
    return json.loads(data)

# If pickle is required, use restricted unpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    SAFE_CLASSES = {'datetime.datetime', 'decimal.Decimal'}

    def find_class(self, module, name):
        if f"{module}.{name}" not in self.SAFE_CLASSES:
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return super().find_class(module, name)

def restricted_loads(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

---

## Attack Scenario 3: Command Injection

**Threat Category**: OWASP A03:2025 - Injection / CWE-78

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Application executes shell command with user input
2. Attacker inputs: file.txt; rm -rf /
3. Command: cat file.txt; rm -rf /
4. Shell interprets ; as command separator
5. Malicious command executes
```

**Mitigation**:
```python
import subprocess
import shlex

def safe_file_info(filename: str) -> str:
    # Validate filename
    if not filename.replace('.', '').replace('_', '').replace('-', '').isalnum():
        raise ValueError("Invalid filename")

    # Never use shell=True with user input
    result = subprocess.run(
        ['file', filename],  # List form, not string
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
```

---

## Attack Scenario 4: Path Traversal

**Threat Category**: OWASP A01:2025 - Broken Access Control / CWE-22

**Threat Level**: HIGH

**Attack Flow**:
```
1. Application reads files based on user input
2. Attacker requests: ../../../etc/passwd
3. Path resolves outside intended directory
4. System file returned to attacker
```

**Mitigation**:
```python
from pathlib import Path

def secure_file_read(base_dir: Path, filename: str) -> bytes:
    # Reject obvious attacks
    if '..' in filename:
        raise ValueError("Invalid path")

    # Resolve and verify containment
    full_path = (base_dir / filename).resolve()
    if not full_path.is_relative_to(base_dir.resolve()):
        raise ValueError("Path traversal detected")

    return full_path.read_bytes()
```

---

## Attack Scenario 5: Weak Cryptography

**Threat Category**: OWASP A02:2025 - Cryptographic Failures / CWE-327

**Threat Level**: HIGH

**Attack Flow**:
```
1. Application uses MD5 for password hashing
2. Attacker obtains password database
3. Uses rainbow tables or GPU cracking
4. MD5 hashes cracked in seconds
5. Attacker has plaintext passwords
```

**Mitigation**:
```python
from argon2 import PasswordHasher

# Use Argon2id with proper parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)

def hash_password(password: str) -> str:
    return ph.hash(password)
```

---

## STRIDE Analysis

| Category | Threats | Mitigations | Priority |
|----------|---------|-------------|----------|
| **Spoofing** | Weak authentication, stolen tokens | MFA, secure sessions, token rotation | HIGH |
| **Tampering** | SQL injection, pickle exploits | Parameterized queries, safe serialization | CRITICAL |
| **Repudiation** | No audit logs | Structured logging with user/action context | MEDIUM |
| **Information Disclosure** | Path traversal, verbose errors | Path containment, safe error messages | HIGH |
| **Denial of Service** | Resource exhaustion, regex DoS | Rate limiting, timeout, regex validation | MEDIUM |
| **Elevation of Privilege** | Command injection, deserialization | No shell=True, safe formats only | CRITICAL |
