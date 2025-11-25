# Python Security Examples Reference

## CVE Details and Mitigations

### CVE-2024-12718: Tarfile Filter Bypass

**Severity**: CRITICAL (CVSS 10.0)
**Affected**: Python 3.12.0 - 3.12.2
**CWE**: CWE-22 (Path Traversal)

**Description**: The tarfile filter parameter (data/tar) fails to properly restrict metadata manipulation, allowing file permission/mtime changes outside extraction directory.

**Vulnerable Code**:
```python
import tarfile

# VULNERABLE
with tarfile.open('archive.tar') as tar:
    tar.extractall(path='/tmp/extract', filter='data')
```

**Mitigation**:
```python
import tarfile
from pathlib import Path

def safe_extract(archive_path: str, dest: str):
    """Extract tar safely with full validation."""
    dest_path = Path(dest).resolve()

    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            # Validate each member path
            member_path = (dest_path / member.name).resolve()
            if not member_path.is_relative_to(dest_path):
                raise ValueError(f"Path traversal: {member.name}")

            # Reject symlinks outside dest
            if member.issym():
                link_target = (dest_path / member.linkname).resolve()
                if not link_target.is_relative_to(dest_path):
                    raise ValueError(f"Symlink escape: {member.name}")

        tar.extractall(path=dest, filter='data')

# Upgrade to Python 3.12.3+
```

---

### CVE-2024-12254: Asyncio Memory Exhaustion

**Severity**: HIGH
**Affected**: Python 3.12.0+
**CWE**: CWE-400 (Resource Exhaustion)

**Description**: `asyncio._SelectorSocketTransport.writelines()` doesn't pause on high-water mark, causing unbounded memory growth.

**Mitigation**:
```python
import asyncio

class SafeProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.write_paused = False

    def connection_made(self, transport):
        self.transport = transport

    def pause_writing(self):
        self.write_paused = True

    def resume_writing(self):
        self.write_paused = False

    async def write_with_backpressure(self, data: bytes):
        while self.write_paused:
            await asyncio.sleep(0.01)
        self.transport.write(data)
```

---

### CVE-2023-50782: Cryptography RSA Timing Attack

**Severity**: HIGH
**Affected**: cryptography < 42.0
**CWE**: CWE-208 (Observable Timing Discrepancy)

**Mitigation**:
```bash
pip install 'cryptography>=42.0'
```

---

## OWASP Top 10 Complete Examples

### A01: Broken Access Control

```python
from functools import wraps
from typing import Callable

def require_permission(permission: str):
    """Decorator to enforce permissions."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, current_user: User, **kwargs):
            if not current_user.has_permission(permission):
                raise PermissionError("Access denied")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@require_permission("admin:delete")
async def delete_user(user_id: int, current_user: User) -> None:
    # Only called if user has permission
    await db.delete(User, user_id)
```

### A02: Cryptographic Failures

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # OWASP recommendation
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data with Fernet (AES-128-CBC + HMAC)."""
    f = Fernet(key)
    return f.encrypt(data)
```

### A03: Injection Prevention

```python
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

# SQL Injection Prevention
async def search_users(db: AsyncSession, query: str) -> list[User]:
    # SAFE: Parameterized query
    stmt = select(User).where(User.name.ilike(f"%{query}%"))
    result = await db.execute(stmt)
    return result.scalars().all()

# Command Injection Prevention
import subprocess

def run_safe_command(filename: str) -> str:
    # Validate input
    if not filename.isalnum():
        raise ValueError("Invalid filename")

    # Never shell=True
    result = subprocess.run(
        ['cat', filename],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
```

### A06: Vulnerable Components

```bash
# Add to CI/CD pipeline
pip-audit --require-hashes --strict
safety check --full-report
```

```python
# requirements.txt with hashes
pydantic==2.5.0 \
    --hash=sha256:abc123...

# Or use poetry with lock file
poetry lock
poetry install --no-dev
```

---

## Additional Security Patterns

### Secure Random Generation

```python
import secrets

# For tokens, keys, passwords
token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)

# For cryptographic operations
from os import urandom
key = urandom(32)
```

### Rate Limiting

```python
from functools import wraps
from time import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.calls = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time()
        self.calls[key] = [t for t in self.calls[key] if t > now - self.period]

        if len(self.calls[key]) >= self.max_calls:
            return False

        self.calls[key].append(now)
        return True

limiter = RateLimiter(max_calls=100, period=60)

def rate_limit(key_func):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs)
            if not limiter.is_allowed(key):
                raise Exception("Rate limited")
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

### Secure Session Management

```python
from datetime import datetime, timedelta
import secrets

class SecureSession:
    def __init__(self):
        self.sessions = {}

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {
            'user_id': user_id,
            'created': datetime.utcnow(),
            'expires': datetime.utcnow() + timedelta(hours=24)
        }
        return token

    def validate(self, token: str) -> int | None:
        session = self.sessions.get(token)
        if not session:
            return None

        if datetime.utcnow() > session['expires']:
            del self.sessions[token]
            return None

        return session['user_id']

    def invalidate(self, token: str) -> None:
        self.sessions.pop(token, None)
```
